package vpn

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func readCRL(t *testing.T, dir string) *x509.RevocationList {
	t.Helper()

	data, err := os.ReadFile(filepath.Join(dir, crlFile))
	if err != nil {
		t.Fatalf("чтение CRL: %v", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("CRL не в формате PEM")
	}
	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		t.Fatalf("разбор CRL: %v", err)
	}
	return crl
}

// CRL должна оставаться валидной для crl-verify даже если сервис неделями
// никого не отзывал: иначе сервер OpenVPN отвергнет всех клиентов.
func TestEnsureFreshCRLExtendsValidityBeforeExpiry(t *testing.T) {
	dir := t.TempDir()
	pki, err := LoadOrCreatePKI(dir)
	if err != nil {
		t.Fatalf("создание PKI: %v", err)
	}

	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	pki.clock = func() time.Time { return base }
	if err := pki.writeCRL(); err != nil {
		t.Fatalf("пересборка CRL: %v", err)
	}

	initial := pki.CRLNextUpdate()
	if !initial.Equal(base.Add(crlValidity)) {
		t.Fatalf("NextUpdate=%v, ожидался %v", initial, base.Add(crlValidity))
	}

	// Свежая CRL не пересобирается.
	if err := pki.EnsureFreshCRL(); err != nil {
		t.Fatalf("EnsureFreshCRL: %v", err)
	}
	if !pki.CRLNextUpdate().Equal(initial) {
		t.Fatal("CRL пересобрана, хотя срок ещё не подходит")
	}

	// За час до истечения окна — пересобирается с новым сроком.
	pki.clock = func() time.Time { return base.Add(crlValidity - time.Hour) }
	if err := pki.EnsureFreshCRL(); err != nil {
		t.Fatalf("EnsureFreshCRL: %v", err)
	}

	refreshed := pki.CRLNextUpdate()
	if !refreshed.After(initial) {
		t.Fatalf("срок действия не продлён: было %v, стало %v", initial, refreshed)
	}

	// Продление должно быть видно в файле, который читает сервер OpenVPN.
	crl := readCRL(t, dir)
	if !crl.NextUpdate.Equal(refreshed) {
		t.Fatalf("в файле NextUpdate=%v, в памяти %v", crl.NextUpdate, refreshed)
	}
	if err := crl.CheckSignatureFrom(pki.caCert); err != nil {
		t.Fatalf("подпись обновлённой CRL недействительна: %v", err)
	}
}

// Свежесть проверяется и при выдаче конфига: сервис не должен раздавать
// доступ, пока лежащая на диске CRL просрочена.
func TestIssueConfigRefreshesStaleCRL(t *testing.T) {
	pkiDir := t.TempDir()
	manager := NewOpenVPNManager(OpenVPNConfig{
		Enabled:  true,
		PKIDir:   pkiDir,
		Endpoint: "vpn.test",
		Port:     1194,
	})

	// Первый выпуск инициализирует PKI и создаёт CRL.
	if _, _, err := manager.IssueConfig(t.Context(), "device-1"); err != nil {
		t.Fatalf("первый выпуск: %v", err)
	}

	staleBefore := readCRL(t, pkiDir).NextUpdate

	// Имитируем простой дольше срока CRL.
	manager.pki.clock = func() time.Time { return staleBefore.Add(-time.Minute) }
	if _, _, err := manager.IssueConfig(t.Context(), "device-2"); err != nil {
		t.Fatalf("выпуск при просроченной CRL: %v", err)
	}

	refreshed := readCRL(t, pkiDir).NextUpdate
	if !refreshed.After(staleBefore) {
		t.Fatalf("CRL не обновлена: было %v, стало %v", staleBefore, refreshed)
	}
}
