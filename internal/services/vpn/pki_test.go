package vpn

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTestPKI(t *testing.T) *PKI {
	t.Helper()

	pki, err := LoadOrCreatePKI(t.TempDir())
	if err != nil {
		t.Fatalf("загрузка PKI: %v", err)
	}
	return pki
}

func parseCertPEM(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()

	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("сертификат не в формате PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("разбор сертификата: %v", err)
	}
	return cert
}

func TestPKICreatesAndPersistsCA(t *testing.T) {
	dir := t.TempDir()

	first, err := LoadOrCreatePKI(dir)
	if err != nil {
		t.Fatalf("создание CA: %v", err)
	}

	for _, name := range []string{caCertFile, caKeyFile, crlFile} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("файл %s не создан: %v", name, err)
		}
	}

	// Повторная загрузка должна использовать тот же CA, иначе ранее выданные
	// клиентские сертификаты перестанут проверяться.
	second, err := LoadOrCreatePKI(dir)
	if err != nil {
		t.Fatalf("повторная загрузка: %v", err)
	}
	if string(second.CAPEM()) != string(first.CAPEM()) {
		t.Fatal("при повторной загрузке создан другой CA")
	}
}

func TestPKIRejectsIncompleteCA(t *testing.T) {
	dir := t.TempDir()

	pki, err := LoadOrCreatePKI(dir)
	if err != nil {
		t.Fatalf("создание: %v", err)
	}
	_ = pki

	// Ключ потерян — молча создавать новый CA нельзя: это сломает доверие.
	if err := os.Remove(filepath.Join(dir, caKeyFile)); err != nil {
		t.Fatalf("удаление ключа: %v", err)
	}

	if _, err := LoadOrCreatePKI(dir); err == nil {
		t.Fatal("ожидалась ошибка при неполном CA")
	}
}

func TestIssueClientCertificateIsSignedByCA(t *testing.T) {
	pki := newTestPKI(t)

	certPEM, keyPEM, serial, err := pki.IssueClient("device-123", time.Hour)
	if err != nil {
		t.Fatalf("выпуск сертификата: %v", err)
	}

	cert := parseCertPEM(t, certPEM)
	if cert.Subject.CommonName != "device-123" {
		t.Fatalf("CN=%q, ожидался device-123", cert.Subject.CommonName)
	}
	if err := cert.CheckSignatureFrom(pki.caCert); err != nil {
		t.Fatalf("подпись CA недействительна: %v", err)
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatalf("неверное назначение сертификата: %v", cert.ExtKeyUsage)
	}
	if serial == "" {
		t.Fatal("серийный номер пуст — отозвать сертификат будет невозможно")
	}
	if cert.SerialNumber.Text(16) != serial {
		t.Fatalf("серийный номер %q не совпадает с сертификатом %q", serial, cert.SerialNumber.Text(16))
	}

	block, _ := pem.Decode(keyPEM)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		t.Fatalf("приватный ключ не в формате EC PRIVATE KEY")
	}
	if _, err := x509.ParseECPrivateKey(block.Bytes); err != nil {
		t.Fatalf("приватный ключ не разбирается: %v", err)
	}
}

func TestIssueClientCertificatesAreUnique(t *testing.T) {
	pki := newTestPKI(t)

	firstCert, _, firstSerial, err := pki.IssueClient("device-1", time.Hour)
	if err != nil {
		t.Fatalf("выпуск: %v", err)
	}
	secondCert, _, secondSerial, err := pki.IssueClient("device-1", time.Hour)
	if err != nil {
		t.Fatalf("выпуск: %v", err)
	}

	if firstSerial == secondSerial {
		t.Fatal("два сертификата получили один серийный номер")
	}
	if string(firstCert) == string(secondCert) {
		t.Fatal("два выпуска вернули один сертификат")
	}
}

func TestIssueClientRejectsBadCommonName(t *testing.T) {
	pki := newTestPKI(t)

	cases := map[string]string{
		"пустое имя":          "",
		"пробелы":             "   ",
		"разметка PEM":        "device</cert><cert>x",
		"перевод строки":      "device\nmalicious",
		"слишком длинное имя": strings.Repeat("a", 65),
	}

	for name, commonName := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, _, err := pki.IssueClient(commonName, time.Hour); err == nil {
				t.Fatal("ожидалась ошибка валидации имени")
			}
		})
	}
}

func TestRevokeWritesSignedCRL(t *testing.T) {
	dir := t.TempDir()
	pki, err := LoadOrCreatePKI(dir)
	if err != nil {
		t.Fatalf("создание PKI: %v", err)
	}

	_, _, serial, err := pki.IssueClient("device-1", time.Hour)
	if err != nil {
		t.Fatalf("выпуск: %v", err)
	}
	if err := pki.Revoke(serial); err != nil {
		t.Fatalf("отзыв: %v", err)
	}

	crlPEM, err := os.ReadFile(filepath.Join(dir, crlFile))
	if err != nil {
		t.Fatalf("чтение CRL: %v", err)
	}
	block, _ := pem.Decode(crlPEM)
	if block == nil || block.Type != "X509 CRL" {
		t.Fatal("CRL не в формате PEM")
	}

	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		t.Fatalf("разбор CRL: %v", err)
	}
	if err := crl.CheckSignatureFrom(pki.caCert); err != nil {
		t.Fatalf("подпись CRL недействительна: %v", err)
	}
	if len(crl.RevokedCertificateEntries) != 1 {
		t.Fatalf("записей в CRL: %d, ожидалась 1", len(crl.RevokedCertificateEntries))
	}
	if crl.RevokedCertificateEntries[0].SerialNumber.Text(16) != serial {
		t.Fatal("в CRL не тот серийный номер")
	}
}

func TestRevokedListSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	pki, err := LoadOrCreatePKI(dir)
	if err != nil {
		t.Fatalf("создание PKI: %v", err)
	}

	_, _, serial, err := pki.IssueClient("device-1", time.Hour)
	if err != nil {
		t.Fatalf("выпуск: %v", err)
	}
	if err := pki.Revoke(serial); err != nil {
		t.Fatalf("отзыв: %v", err)
	}

	restarted, err := LoadOrCreatePKI(dir)
	if err != nil {
		t.Fatalf("перезагрузка: %v", err)
	}
	if _, ok := restarted.revoked[serial]; !ok {
		t.Fatal("после рестарта отозванный сертификат потерян")
	}

	crlPEM, err := os.ReadFile(filepath.Join(dir, crlFile))
	if err != nil {
		t.Fatalf("чтение CRL: %v", err)
	}
	block, _ := pem.Decode(crlPEM)
	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		t.Fatalf("разбор CRL: %v", err)
	}
	if len(crl.RevokedCertificateEntries) != 1 {
		t.Fatalf("записей в CRL после рестарта: %d, ожидалась 1", len(crl.RevokedCertificateEntries))
	}
}

func TestRevokeIsIdempotentAndValidatesSerial(t *testing.T) {
	pki := newTestPKI(t)

	_, _, serial, err := pki.IssueClient("device-1", time.Hour)
	if err != nil {
		t.Fatalf("выпуск: %v", err)
	}

	if err := pki.Revoke(serial); err != nil {
		t.Fatalf("первый отзыв: %v", err)
	}
	if err := pki.Revoke(serial); err != nil {
		t.Fatalf("повторный отзыв должен быть идемпотентным: %v", err)
	}
	if err := pki.Revoke("не-серийник"); err == nil {
		t.Fatal("ожидалась ошибка для некорректного серийного номера")
	}
	if err := pki.Revoke(""); err != nil {
		t.Fatalf("пустой серийный номер должен игнорироваться: %v", err)
	}
}
