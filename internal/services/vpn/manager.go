package vpn

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"vpn-service/internal/storage/models"
	"vpn-service/pkg/utils"
)

// Ошибки уровня сервиса: по ним хендлеры выбирают HTTP-код, не разбирая
// тексты ошибок и не зная о деталях хранилища.
var (
	ErrDeviceNotFound         = errors.New("device not found")
	ErrUnsupportedProtocol    = errors.New("unsupported protocol")
	ErrWireGuardNotConfigured = errors.New("wireguard is not configured")
	ErrOpenVPNNotConfigured   = errors.New("openvpn is not configured")
)

const (
	ProtocolWireGuard = "wireguard"
	ProtocolOpenVPN   = "openvpn"

	// ipAllocationAttempts — сколько раз пытаться вставить устройство, если
	// параллельный запрос занял выбранный адрес. Окончательную защиту даёт
	// уникальный индекс в БД, а не этот счётчик.
	ipAllocationAttempts = 2
)

// WireGuardConfig конфигурация WireGuard
type WireGuardConfig struct {
	InterfaceName string
	Port          int
	PrivateKey    string
	PublicKey     string
	NetworkCIDR   string
	// Endpoint — хост, который попадает в клиентский конфиг.
	Endpoint string
	// DNS и AllowedIPs подставляются в клиентский конфиг.
	DNS        string
	AllowedIPs string
	// Enabled включает применение пиров к интерфейсу через wg.
	Enabled bool
}

// OpenVPNConfig конфигурация OpenVPN
type OpenVPNConfig struct {
	ConfigPath  string
	Port        int
	NetworkCIDR string
	// Enabled включает выдачу клиентских сертификатов через встроенный CA.
	Enabled bool
	// PKIDir — каталог с CA, CRL и списком отозванных сертификатов.
	PKIDir   string
	Endpoint string
	Proto    string
}

// DeviceStore — часть хранилища устройств, которая нужна менеджеру.
// Интерфейс позволяет тестировать менеджер и хендлеры без реальной БД.
type DeviceStore interface {
	CreateDevice(ctx context.Context, device *models.Device) error
	GetDeviceForUser(ctx context.Context, id, userID string) (*models.Device, error)
	GetDevicesByUser(ctx context.Context, userID string) ([]models.Device, error)
	UpdateDeviceStatus(ctx context.Context, id, status string) error
	DeleteDevice(ctx context.Context, id string) error
	// ListAllocatedIPs возвращает адреса, занятые неотозванными устройствами.
	ListAllocatedIPs(ctx context.Context) ([]string, error)
	// SetDeviceCertSerial сохраняет серийный номер сертификата OpenVPN,
	// чтобы устройство можно было отозвать.
	SetDeviceCertSerial(ctx context.Context, id, serial string) error
}

type Manager struct {
	db          DeviceStore
	wgManager   *WireGuardManager
	ovpnManager *OpenVPNManager
	wgConfig    WireGuardConfig
}

func NewManager(db DeviceStore, wgConfig WireGuardConfig, ovpnConfig OpenVPNConfig) *Manager {
	return &Manager{
		db:          db,
		wgManager:   NewWireGuardManager(wgConfig),
		ovpnManager: NewOpenVPNManager(ovpnConfig),
		wgConfig:    wgConfig,
	}
}

func (m *Manager) CreateDevice(ctx context.Context, userID, deviceName, protocol string) (*models.Device, error) {
	// Протокол проверяется до записи в БД, чтобы не оставлять мусорные строки.
	if protocol != ProtocolWireGuard && protocol != ProtocolOpenVPN {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedProtocol, protocol)
	}

	privateKey, publicKey, err := deviceKeys(protocol)
	if err != nil {
		return nil, err
	}

	// Интерфейс проверяется до записи в БД: если поднять его не удалось,
	// компенсировать нечего и клиент получает внятную ошибку.
	if protocol == ProtocolWireGuard {
		if err := m.wgManager.EnsureInterface(ctx); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrWireGuardNotConfigured, err)
		}
	}

	now := time.Now()
	device := &models.Device{
		ID:         utils.GenerateUUID(),
		UserID:     userID,
		Name:       deviceName,
		Protocol:   protocol,
		DeviceKey:  privateKey,
		PublicKey:  publicKey,
		Status:     "active",
		CreatedAt:  now,
		UpdatedAt:  now,
		LastActive: now,
	}

	if err := m.insertWithAddress(ctx, device); err != nil {
		return nil, err
	}

	var applyErr error
	switch protocol {
	case ProtocolWireGuard:
		applyErr = m.wgManager.AddPeer(ctx, device.PublicKey, device.IPAddress)
	case ProtocolOpenVPN:
		applyErr = m.ovpnManager.AddClient(ctx, device.ID)
	}
	if applyErr != nil {
		// Компенсация: без неё в БД осталось бы устройство в статусе active,
		// которому не соответствует ни один пир.
		if cleanupErr := m.db.DeleteDevice(ctx, device.ID); cleanupErr != nil {
			return nil, fmt.Errorf("failed to register %s peer: %w (cleanup failed: %v)", protocol, applyErr, cleanupErr)
		}
		return nil, fmt.Errorf("failed to register %s peer: %w", protocol, applyErr)
	}

	return device, nil
}

// insertWithAddress подбирает свободный адрес и вставляет устройство.
// При конфликте адреса (параллельный запрос успел раньше) попытка повторяется.
func (m *Manager) insertWithAddress(ctx context.Context, device *models.Device) error {
	var lastErr error

	for attempt := 0; attempt < ipAllocationAttempts; attempt++ {
		used, err := m.usedAddresses(ctx)
		if err != nil {
			return err
		}

		address, err := allocateIP(m.wgConfig.NetworkCIDR, used)
		if err != nil {
			return err
		}
		device.IPAddress = address

		if err := m.db.CreateDevice(ctx, device); err != nil {
			lastErr = err
			continue
		}
		return nil
	}

	return lastErr
}

func (m *Manager) usedAddresses(ctx context.Context) (map[string]struct{}, error) {
	addresses, err := m.db.ListAllocatedIPs(ctx)
	if err != nil {
		return nil, err
	}

	used := make(map[string]struct{}, len(addresses))
	for _, address := range addresses {
		used[address] = struct{}{}
	}
	return used, nil
}

// GetDeviceConfig возвращает конфигурацию только для устройства, принадлежащего userID.
func (m *Manager) GetDeviceConfig(ctx context.Context, userID, deviceID string) (string, error) {
	device, err := m.db.GetDeviceForUser(ctx, deviceID, userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrDeviceNotFound
		}
		return "", err
	}

	switch device.Protocol {
	case ProtocolWireGuard:
		return m.wgManager.GetConfig(ClientConfig{
			PrivateKey: device.DeviceKey,
			Address:    device.IPAddress,
		})
	case ProtocolOpenVPN:
		// Один активный сертификат на устройство: предыдущий отзывается,
		// иначе у пользователя оставался бы рабочий дубликат.
		if device.CertSerial != "" {
			if err := m.ovpnManager.Revoke(device.CertSerial); err != nil {
				return "", err
			}
		}

		config, serial, err := m.ovpnManager.IssueConfig(ctx, device.ID)
		if err != nil {
			return "", err
		}
		if serial != "" {
			if err := m.db.SetDeviceCertSerial(ctx, device.ID, serial); err != nil {
				return "", fmt.Errorf("save certificate serial: %w", err)
			}
		}
		return config, nil
	default:
		return "", fmt.Errorf("%w: %s", ErrUnsupportedProtocol, device.Protocol)
	}
}

// RevokeDevice отзывает устройство; чужое устройство неотличимо от несуществующего.
func (m *Manager) RevokeDevice(ctx context.Context, userID, deviceID string) error {
	device, err := m.db.GetDeviceForUser(ctx, deviceID, userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrDeviceNotFound
		}
		return err
	}

	if device.Status == "revoked" {
		return nil
	}

	switch device.Protocol {
	case ProtocolWireGuard:
		if err := m.wgManager.RemovePeer(ctx, device.PublicKey); err != nil {
			return err
		}
	case ProtocolOpenVPN:
		if device.CertSerial != "" {
			if err := m.ovpnManager.Revoke(device.CertSerial); err != nil {
				return err
			}
		}
	}

	return m.db.UpdateDeviceStatus(ctx, deviceID, "revoked")
}

func (m *Manager) GetDevicesByUser(ctx context.Context, userID string) ([]models.Device, error) {
	return m.db.GetDevicesByUser(ctx, userID)
}

// deviceKeys возвращает приватный ключ устройства и публичный ключ пира.
// Для WireGuard это настоящая пара Curve25519; для OpenVPN — случайный
// идентификатор, пока PKI не реализована.
func deviceKeys(protocol string) (privateKey, publicKey string, err error) {
	if protocol == ProtocolWireGuard {
		return generateWireGuardKeyPair()
	}
	token, err := generateDeviceKey()
	if err != nil {
		return "", "", err
	}
	return token, "", nil
}

// generateDeviceKey создаёт случайный идентификатор для протоколов без
// ключевой пары (OpenVPN — пока не подключена PKI).
func generateDeviceKey() (string, error) {
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return "", fmt.Errorf("generate device key: %w", err)
	}
	return base64.URLEncoding.EncodeToString(token), nil
}
