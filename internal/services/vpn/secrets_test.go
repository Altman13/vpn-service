package vpn

import (
	"context"
	"strings"
	"testing"

	"vpn-service/internal/storage/models"
	"vpn-service/pkg/secretbox"
)

func testBox(t *testing.T, fill byte) *secretbox.Box {
	t.Helper()

	key := make([]byte, 32)
	for i := range key {
		key[i] = fill
	}
	box, err := secretbox.New(key)
	if err != nil {
		t.Fatalf("создание шифра: %v", err)
	}
	return box
}

func privateKeyFromConfig(t *testing.T, config string) string {
	t.Helper()

	for _, line := range strings.Split(config, "\n") {
		if strings.HasPrefix(line, "PrivateKey = ") {
			return strings.TrimPrefix(line, "PrivateKey = ")
		}
	}
	t.Fatalf("в конфиге нет PrivateKey:\n%s", config)
	return ""
}

// Приватный ключ устройства не должен лежать в БД открытым текстом.
func TestDeviceKeyIsEncryptedAtRest(t *testing.T) {
	store := newMemStore()
	manager := newTestManager(store)
	manager.UseSecretBox(testBox(t, 0x11))

	device, err := manager.CreateDevice(context.Background(), "user-1", "laptop", ProtocolWireGuard)
	if err != nil {
		t.Fatalf("создание устройства: %v", err)
	}

	stored := store.devices[device.ID].DeviceKey
	if !secretbox.IsSealed(stored) {
		t.Fatalf("ключ в БД не зашифрован: %q", stored)
	}

	config, err := manager.GetDeviceConfig(context.Background(), "user-1", device.ID)
	if err != nil {
		t.Fatalf("получение конфига: %v", err)
	}

	key := privateKeyFromConfig(t, config)
	if secretbox.IsSealed(key) {
		t.Fatal("в конфиг попал шифротекст вместо ключа")
	}
	if len(key) != 44 {
		t.Fatalf("длина ключа в конфиге %d, ожидалось 44", len(key))
	}
}

// Ключ, зашифрованный другим ключом сервиса, не должен расшифровываться.
func TestDeviceKeyCannotBeOpenedWithAnotherKey(t *testing.T) {
	store := newMemStore()

	first := newTestManager(store)
	first.UseSecretBox(testBox(t, 0x22))
	device, err := first.CreateDevice(context.Background(), "user-1", "laptop", ProtocolWireGuard)
	if err != nil {
		t.Fatalf("создание устройства: %v", err)
	}

	second := newTestManager(store)
	second.UseSecretBox(testBox(t, 0x33))

	if _, err := second.GetDeviceConfig(context.Background(), "user-1", device.ID); err == nil {
		t.Fatal("ключ расшифрован чужим ключом сервиса")
	}
}

// Записи, созданные до включения шифрования, должны продолжать работать.
func TestLegacyPlaintextKeyStillWorks(t *testing.T) {
	store := newMemStore()
	store.devices["legacy-device"] = &models.Device{
		ID:        "legacy-device",
		UserID:    "user-1",
		Name:      "old",
		Protocol:  ProtocolWireGuard,
		DeviceKey: "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=",
		IPAddress: "10.0.0.2",
		Status:    "active",
	}

	manager := newTestManager(store)
	manager.UseSecretBox(testBox(t, 0x44))

	config, err := manager.GetDeviceConfig(context.Background(), "user-1", "legacy-device")
	if err != nil {
		t.Fatalf("конфиг для старой записи: %v", err)
	}
	if key := privateKeyFromConfig(t, config); key != "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=" {
		t.Fatalf("ключ изменён: %q", key)
	}
}
