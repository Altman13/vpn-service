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

// WireGuardConfig конфигурация WireGuard
type WireGuardConfig struct {
	InterfaceName string
	Port          int
	PrivateKey    string
	PublicKey     string
	NetworkCIDR   string
}

// OpenVPNConfig конфигурация OpenVPN
type OpenVPNConfig struct {
	ConfigPath  string
	Port        int
	NetworkCIDR string
}

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
	deviceKey := generateDeviceKey()
	ipAddress := generateIPAddress()

	device := &models.Device{
		ID:         utils.GenerateUUID(),
		UserID:     userID,
		Name:       deviceName,
		Protocol:   protocol,
		DeviceKey:  deviceKey,
		IPAddress:  ipAddress,
		Status:     "active",
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
		LastActive: time.Now(),
	}

	if err := m.db.CreateDevice(ctx, device); err != nil {
		return nil, err
	}

	switch protocol {
	case "wireguard":
		if err := m.wgManager.AddPeer(ctx, device.ID, device.DeviceKey); err != nil {
			return nil, fmt.Errorf("failed to add wireguard peer: %w", err)
		}
	case "openvpn":
		if err := m.ovpnManager.AddClient(ctx, device.ID, device.DeviceKey); err != nil {
			return nil, fmt.Errorf("failed to add openvpn client: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", protocol)
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

func generateIPAddress() string {
	return fmt.Sprintf("10.0.0.%d", time.Now().UnixNano()%254+1)
}
