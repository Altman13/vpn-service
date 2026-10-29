package vpn

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func openVPNManagerFor(t *testing.T, store DeviceStore) (*Manager, string) {
	t.Helper()

	dir := t.TempDir()
	manager := NewManager(store,
		WireGuardConfig{
			PublicKey:   "server-public-key",
			NetworkCIDR: "10.0.0.0/24",
			Endpoint:    "vpn.test",
			Port:        51820,
		},
		OpenVPNConfig{
			Enabled:     true,
			PKIDir:      dir,
			Endpoint:    "vpn.test",
			Port:        1194,
			Proto:       "udp",
			NetworkCIDR: "10.8.0.0/24",
		},
	)
	return manager, dir
}

func crlSerials(t *testing.T, dir string) []string {
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

	serials := make([]string, 0, len(crl.RevokedCertificateEntries))
	for _, entry := range crl.RevokedCertificateEntries {
		serials = append(serials, entry.SerialNumber.Text(16))
	}
	return serials
}

func TestOpenVPNIsDisabledByDefault(t *testing.T) {
	manager := NewOpenVPNManager(OpenVPNConfig{})
	ctx := context.Background()

	if err := manager.AddClient(ctx, "device-1"); !errors.Is(err, ErrOpenVPNNotConfigured) {
		t.Fatalf("AddClient: ожидалась ErrOpenVPNNotConfigured, получено %v", err)
	}
	if _, _, err := manager.IssueConfig(ctx, "device-1"); !errors.Is(err, ErrOpenVPNNotConfigured) {
		t.Fatalf("IssueConfig: ожидалась ErrOpenVPNNotConfigured, получено %v", err)
	}
	if err := manager.Revoke("abc"); !errors.Is(err, ErrOpenVPNNotConfigured) {
		t.Fatalf("Revoke: ожидалась ErrOpenVPNNotConfigured, получено %v", err)
	}
}

func TestOpenVPNRequiresEndpoint(t *testing.T) {
	manager := NewOpenVPNManager(OpenVPNConfig{
		Enabled: true,
		PKIDir:  t.TempDir(),
		Port:    1194,
	})

	if _, _, err := manager.IssueConfig(context.Background(), "device-1"); !errors.Is(err, ErrOpenVPNNotConfigured) {
		t.Fatalf("ожидалась ErrOpenVPNNotConfigured без endpoint, получено %v", err)
	}
}

func TestOpenVPNIssueConfigBuildsClientFile(t *testing.T) {
	pkiDir := t.TempDir()
	manager := NewOpenVPNManager(OpenVPNConfig{
		Enabled:  true,
		PKIDir:   pkiDir,
		Endpoint: "vpn.test",
		Port:     1194,
		Proto:    "tcp",
	})

	config, serial, err := manager.IssueConfig(context.Background(), "device-1")
	if err != nil {
		t.Fatalf("выпуск конфига: %v", err)
	}

	for _, want := range []string{
		"client",
		"dev tun",
		"proto tcp",
		"remote vpn.test 1194",
		"remote-cert-tls server",
		"<ca>",
		"<cert>",
		"<key>",
	} {
		if !strings.Contains(config, want) {
			t.Fatalf("в конфиге нет %q:\n%s", want, config)
		}
	}

	// Внутри блоков OpenVPN ожидает только base64, без PEM-заголовков,
	// иначе он не сможет разобрать конфиг.
	if strings.Contains(config, "-----BEGIN") || strings.Contains(config, "-----END") {
		t.Fatalf("в конфиг попали PEM-заголовки:\n%s", config)
	}
	if serial == "" {
		t.Fatal("серийный номер не возвращён")
	}
}

// Полный цикл: создание устройства, выдача конфига, ротация сертификата
// при повторной выдаче и отзыв при удалении устройства.
func TestOpenVPNDeviceLifecycle(t *testing.T) {
	store := newMemStore()
	manager, pkiDir := openVPNManagerFor(t, store)
	ctx := context.Background()

	device, err := manager.CreateDevice(ctx, "user-1", "laptop", ProtocolOpenVPN)
	if err != nil {
		t.Fatalf("создание устройства: %v", err)
	}
	if device.IPAddress == "" {
		t.Fatal("устройству не выдан адрес")
	}

	if _, err := manager.GetDeviceConfig(ctx, "user-1", device.ID); err != nil {
		t.Fatalf("первый конфиг: %v", err)
	}
	firstSerial := store.devices[device.ID].CertSerial
	if firstSerial == "" {
		t.Fatal("серийный номер сертификата не сохранён")
	}
	if serials := crlSerials(t, pkiDir); len(serials) != 0 {
		t.Fatalf("до ротации в CRL уже есть записи: %v", serials)
	}

	// Повторная выдача должна погасить предыдущий сертификат.
	if _, err := manager.GetDeviceConfig(ctx, "user-1", device.ID); err != nil {
		t.Fatalf("второй конфиг: %v", err)
	}
	secondSerial := store.devices[device.ID].CertSerial
	if secondSerial == firstSerial {
		t.Fatal("сертификат не сменился при повторной выдаче")
	}
	if serials := crlSerials(t, pkiDir); len(serials) != 1 || serials[0] != firstSerial {
		t.Fatalf("старый сертификат не отозван, CRL: %v", serials)
	}

	if err := manager.RevokeDevice(ctx, "user-1", device.ID); err != nil {
		t.Fatalf("отзыв устройства: %v", err)
	}
	if store.devices[device.ID].Status != "revoked" {
		t.Fatal("устройство не помечено отозванным")
	}
	serials := crlSerials(t, pkiDir)
	if len(serials) != 2 || serials[0] == serials[1] {
		t.Fatalf("CRL после отзыва устройства: %v", serials)
	}
}
