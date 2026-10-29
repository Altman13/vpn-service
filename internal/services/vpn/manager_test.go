package vpn

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"vpn-service/internal/storage/models"
)

// memStore повторяет поведение SQL-хранилища, включая частичный уникальный
// индекс по ip_address: адрес выделяется до вставки, а конфликт отвергается.
type memStore struct {
	devices map[string]*models.Device
}

func newMemStore() *memStore {
	return &memStore{devices: make(map[string]*models.Device)}
}

func (s *memStore) CreateDeviceWithAddress(_ context.Context, device *models.Device, allocate func(used []string) (string, error)) error {
	used := make([]string, 0, len(s.devices))
	for _, existing := range s.devices {
		if existing.Status != "revoked" && existing.IPAddress != "" {
			used = append(used, existing.IPAddress)
		}
	}

	address, err := allocate(used)
	if err != nil {
		return err
	}
	device.IPAddress = address

	for _, existing := range s.devices {
		if existing.Status != "revoked" && existing.IPAddress == address {
			return errors.New("duplicate key value violates unique constraint \"idx_devices_ip_active\"")
		}
	}

	copied := *device
	s.devices[device.ID] = &copied
	return nil
}

func (s *memStore) GetDeviceForUser(_ context.Context, id, userID string) (*models.Device, error) {
	device, ok := s.devices[id]
	if !ok || device.UserID != userID {
		return nil, sql.ErrNoRows
	}
	return device, nil
}

func (s *memStore) GetDevicesByUser(_ context.Context, userID string) ([]models.Device, error) {
	result := make([]models.Device, 0, len(s.devices))
	for _, device := range s.devices {
		if device.UserID == userID {
			result = append(result, *device)
		}
	}
	return result, nil
}

func (s *memStore) UpdateDeviceStatus(_ context.Context, id, status string) error {
	if device, ok := s.devices[id]; ok {
		device.Status = status
	}
	return nil
}

func (s *memStore) DeleteDevice(_ context.Context, id string) error {
	delete(s.devices, id)
	return nil
}

func (s *memStore) SetDeviceKey(_ context.Context, id, key string) error {
	if device, ok := s.devices[id]; ok {
		device.DeviceKey = key
	}
	return nil
}

func (s *memStore) SetDeviceCertSerial(_ context.Context, id, serial string) error {
	if device, ok := s.devices[id]; ok {
		device.CertSerial = serial
	}
	return nil
}

func newTestManager(store DeviceStore) *Manager {
	return NewManager(store,
		WireGuardConfig{
			InterfaceName: "wg0",
			Port:          51820,
			PublicKey:     "server-public-key",
			NetworkCIDR:   "10.0.0.0/24",
			Endpoint:      "vpn.example.com",
			DNS:           "1.1.1.1",
			AllowedIPs:    "0.0.0.0/0",
		},
		OpenVPNConfig{Port: 1194, NetworkCIDR: "10.8.0.0/24"},
	)
}

func TestCreateDeviceAllocatesUniqueAddressesAndValidKeys(t *testing.T) {
	store := newMemStore()
	manager := newTestManager(store)
	ctx := context.Background()

	first, err := manager.CreateDevice(ctx, "user-1", "laptop", ProtocolWireGuard)
	if err != nil {
		t.Fatalf("первое устройство: %v", err)
	}
	second, err := manager.CreateDevice(ctx, "user-1", "phone", ProtocolWireGuard)
	if err != nil {
		t.Fatalf("второе устройство: %v", err)
	}

	if first.IPAddress != "10.0.0.2" || second.IPAddress != "10.0.0.3" {
		t.Fatalf("адреса %q и %q, ожидались 10.0.0.2 и 10.0.0.3", first.IPAddress, second.IPAddress)
	}
	for _, device := range []*models.Device{first, second} {
		privateRaw, err := base64.StdEncoding.DecodeString(device.DeviceKey)
		if err != nil || len(privateRaw) != wireGuardKeySize {
			t.Fatalf("приватный ключ устройства невалиден: %q (%v)", device.DeviceKey, err)
		}
		publicRaw, err := base64.StdEncoding.DecodeString(device.PublicKey)
		if err != nil || len(publicRaw) != wireGuardKeySize {
			t.Fatalf("публичный ключ устройства невалиден: %q (%v)", device.PublicKey, err)
		}
	}
	if first.PublicKey == second.PublicKey {
		t.Fatal("устройства получили одинаковый публичный ключ")
	}
}

func TestCreateDeviceReusesAddressAfterRevoke(t *testing.T) {
	store := newMemStore()
	manager := newTestManager(store)
	ctx := context.Background()

	first, err := manager.CreateDevice(ctx, "user-1", "laptop", ProtocolWireGuard)
	if err != nil {
		t.Fatalf("создание: %v", err)
	}
	if err := manager.RevokeDevice(ctx, "user-1", first.ID); err != nil {
		t.Fatalf("отзыв: %v", err)
	}

	second, err := manager.CreateDevice(ctx, "user-1", "phone", ProtocolWireGuard)
	if err != nil {
		t.Fatalf("создание после отзыва: %v", err)
	}
	if second.IPAddress != first.IPAddress {
		t.Fatalf("освободившийся адрес %s не переиспользован, выдан %s", first.IPAddress, second.IPAddress)
	}
}

// Если свободных адресов нет, устройство не создаётся и в БД ничего не остаётся.
func TestCreateDeviceFailsWhenSubnetIsExhausted(t *testing.T) {
	store := newMemStore()
	manager := newTestManager(store)
	manager.wgConfig.NetworkCIDR = "10.0.0.0/30" // .1 — шлюз, .3 — broadcast, клиенту только .2
	store.devices["taken"] = &models.Device{
		ID:        "taken",
		UserID:    "user-2",
		Protocol:  ProtocolWireGuard,
		IPAddress: "10.0.0.2",
		Status:    "active",
	}

	_, err := manager.CreateDevice(context.Background(), "user-1", "laptop", ProtocolWireGuard)
	if err == nil {
		t.Fatal("ожидалась ошибка: свободных адресов нет")
	}
	if len(store.devices) != 1 {
		t.Fatalf("в хранилище добавились устройства: %d", len(store.devices))
	}
}

// Если пир не применился, запись в БД не должна остаться.
func TestCreateDeviceCompensatesWhenPeerApplyFails(t *testing.T) {
	store := newMemStore()
	manager := newTestManager(store)
	manager.wgManager.enabled = true
	manager.wgManager.runner = &recordingRunner{failOn: map[string]error{
		"wg set": errors.New("wg: Operation not permitted"),
	}}

	if _, err := manager.CreateDevice(context.Background(), "user-1", "laptop", ProtocolWireGuard); err == nil {
		t.Fatal("ожидалась ошибка применения пира")
	}
	if len(store.devices) != 0 {
		t.Fatalf("после ошибки осталось %d устройств, ожидалось 0", len(store.devices))
	}
}

func TestCreateDeviceRejectsUnsupportedProtocol(t *testing.T) {
	manager := newTestManager(newMemStore())

	_, err := manager.CreateDevice(context.Background(), "user-1", "laptop", "pptp")
	if !errors.Is(err, ErrUnsupportedProtocol) {
		t.Fatalf("ожидалась ErrUnsupportedProtocol, получено %v", err)
	}
}

// OpenVPN пока не реализован, поэтому создание обязано упасть явно, а не
// оставить «рабочее» устройство без конфига.
func TestCreateDeviceOpenVPNFailsExplicitly(t *testing.T) {
	store := newMemStore()
	manager := newTestManager(store)

	_, err := manager.CreateDevice(context.Background(), "user-1", "laptop", ProtocolOpenVPN)
	if !errors.Is(err, ErrOpenVPNNotConfigured) {
		t.Fatalf("ожидалась ErrOpenVPNNotConfigured, получено %v", err)
	}
	if len(store.devices) != 0 {
		t.Fatalf("устройство OpenVPN осталось в БД: %d", len(store.devices))
	}
}

func TestGetDeviceConfigUsesAllocatedAddress(t *testing.T) {
	store := newMemStore()
	manager := newTestManager(store)
	ctx := context.Background()

	device, err := manager.CreateDevice(ctx, "user-1", "laptop", ProtocolWireGuard)
	if err != nil {
		t.Fatalf("создание: %v", err)
	}

	config, err := manager.GetDeviceConfig(ctx, "user-1", device.ID)
	if err != nil {
		t.Fatalf("конфиг: %v", err)
	}
	if !strings.Contains(config, "Address = 10.0.0.2/32") {
		t.Fatalf("в конфиге нет выданного адреса:\n%s", config)
	}
	if !strings.Contains(config, "PrivateKey = "+device.DeviceKey) {
		t.Fatalf("в конфиге нет ключа устройства:\n%s", config)
	}
}

// Отзыв должен снимать пира по публичному ключу: приватный ключ клиента
// серверу для этого не нужен и не должен попадать в команду.
func TestRevokeDeviceRemovesPeerByPublicKey(t *testing.T) {
	store := newMemStore()
	manager := newTestManager(store)
	manager.wgManager.enabled = true
	runner := &recordingRunner{}
	manager.wgManager.runner = runner
	ctx := context.Background()

	device, err := manager.CreateDevice(ctx, "user-1", "laptop", ProtocolWireGuard)
	if err != nil {
		t.Fatalf("создание: %v", err)
	}
	runner.calls = nil

	if err := manager.RevokeDevice(ctx, "user-1", device.ID); err != nil {
		t.Fatalf("отзыв: %v", err)
	}

	want := "wg set wg0 peer " + device.PublicKey + " remove"
	if len(runner.calls) != 1 || strings.Join(runner.calls[0], " ") != want {
		t.Fatalf("команда отзыва: %v, ожидалась %q", runner.calls, want)
	}
	for _, call := range runner.calls {
		if strings.Contains(strings.Join(call, " "), device.DeviceKey) {
			t.Fatal("приватный ключ устройства попал в аргументы wg")
		}
	}
}

func TestRevokeDeviceRejectsForeignDevice(t *testing.T) {
	store := newMemStore()
	manager := newTestManager(store)
	ctx := context.Background()

	device, err := manager.CreateDevice(ctx, "user-1", "laptop", ProtocolWireGuard)
	if err != nil {
		t.Fatalf("создание: %v", err)
	}

	if err := manager.RevokeDevice(ctx, "user-2", device.ID); !errors.Is(err, ErrDeviceNotFound) {
		t.Fatalf("ожидалась ErrDeviceNotFound, получено %v", err)
	}
	if device.Status != "active" {
		t.Fatalf("чужое устройство изменено: статус %s", device.Status)
	}
}
