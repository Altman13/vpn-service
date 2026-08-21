package vpn

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"vpn-service/internal/storage/models"
	"vpn-service/internal/storage/postgres"
	"vpn-service/pkg/utils"
)

type Manager struct {
	db          *postgres.DB
	wgManager   *WireGuardManager
	ovpnManager *OpenVPNManager
}

func NewManager(db *postgres.DB, wgConfig WireGuardConfig, ovpnConfig OpenVPNConfig) *Manager {
	return &Manager{
		db:          db,
		wgManager:   NewWireGuardManager(wgConfig),
		ovpnManager: NewOpenVPNManager(ovpnConfig),
	}
}

func (m *Manager) CreateDevice(ctx context.Context, userID, deviceName, protocol string) (*models.Device, error) {
	// Генерация уникального ключа устройства
	key := generateDeviceKey()

	device := &models.Device{
		ID:        utils.GenerateUUID(),
		UserID:    userID,
		Name:      deviceName,
		Protocol:  protocol,
		DeviceKey: key,
		Status:    "active",
		CreatedAt: time.Now(),
	}

	// Сохранение в БД
	if err := m.db.CreateDevice(ctx, device); err != nil {
		return nil, err
	}

	// Настройка VPN в зависимости от протокола
	switch protocol {
	case "wireguard":
		if err := m.wgManager.AddPeer(ctx, device.ID, device.DeviceKey); err != nil {
			return nil, err
		}
	case "openvpn":
		if err := m.ovpnManager.AddClient(ctx, device.ID, device.DeviceKey); err != nil {
			return nil, err
		}
	}

	return device, nil
}

func (m *Manager) GetDeviceConfig(ctx context.Context, deviceID string) (string, error) {
	device, err := m.db.GetDevice(ctx, deviceID)
	if err != nil {
		return "", err
	}

	switch device.Protocol {
	case "wireguard":
		return m.wgManager.GetConfig(device.ID, device.DeviceKey)
	case "openvpn":
		return m.ovpnManager.GetConfig(device.ID, device.DeviceKey)
	default:
		return "", fmt.Errorf("unsupported protocol: %s", device.Protocol)
	}
}

func (m *Manager) RevokeDevice(ctx context.Context, deviceID string) error {
	device, err := m.db.GetDevice(ctx, deviceID)
	if err != nil {
		return err
	}

	// Удаление из VPN
	switch device.Protocol {
	case "wireguard":
		if err := m.wgManager.RemovePeer(ctx, deviceID); err != nil {
			return err
		}
	case "openvpn":
		if err := m.ovpnManager.RemoveClient(ctx, deviceID); err != nil {
			return err
		}
	}

	// Обновление статуса в БД
	return m.db.UpdateDeviceStatus(ctx, deviceID, "revoked")
}

func (m *Manager) GetDevicesByUser(ctx context.Context, userID string) ([]models.Device, error) {
	return m.db.GetDevicesByUser(ctx, userID)
}

func generateDeviceKey() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return base64.URLEncoding.EncodeToString(bytes)
}
