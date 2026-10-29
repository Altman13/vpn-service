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

// Записи, созданные до включения шифрования, перешифровываются при первом
// чтении: иначе они остались бы открытыми навсегда.
func TestLegacyKeyIsReencryptedOnRead(t *testing.T) {
	store := newMemStore()
	store.devices["legacy"] = &models.Device{
		ID:        "legacy",
		UserID:    "user-1",
		Name:      "old",
		Protocol:  ProtocolWireGuard,
		DeviceKey: "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=",
		IPAddress: "10.0.0.2",
		Status:    "active",
	}

	manager := newTestManager(store)
	manager.UseSecretBox(testBox(t, 0x66))

	if _, err := manager.GetDeviceConfig(context.Background(), "user-1", "legacy"); err != nil {
		t.Fatalf("первая выдача конфига: %v", err)
	}

	stored := store.devices["legacy"].DeviceKey
	if !secretbox.IsSealed(stored) {
		t.Fatalf("ключ не перешифрован: %q", stored)
	}

	// Повторная выдача должна работать уже с зашифрованным значением.
	config, err := manager.GetDeviceConfig(context.Background(), "user-1", "legacy")
	if err != nil {
		t.Fatalf("вторая выдача конфига: %v", err)
	}
	if key := privateKeyFromConfig(t, config); key != "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=" {
		t.Fatalf("ключ изменился после перешифровки: %q", key)
	}
}

// Без настроенного шифрования ключ не должен трогаться вовсе.
func TestKeyIsNotTouchedWithoutSecretBox(t *testing.T) {
	store := newMemStore()
	const plain = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="
	store.devices["plain"] = &models.Device{
		ID:        "plain",
		UserID:    "user-1",
		Name:      "old",
		Protocol:  ProtocolWireGuard,
		DeviceKey: plain,
		IPAddress: "10.0.0.2",
		Status:    "active",
	}

	manager := newTestManager(store)
	if _, err := manager.GetDeviceConfig(context.Background(), "user-1", "plain"); err != nil {
		t.Fatalf("выдача конфига: %v", err)
	}
	if store.devices["plain"].DeviceKey != plain {
		t.Fatalf("ключ изменён без шифрования: %q", store.devices["plain"].DeviceKey)
	}
}
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
