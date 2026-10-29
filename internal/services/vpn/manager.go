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
	"vpn-service/pkg/secretbox"
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
	// CreateDeviceWithAddress выделяет адрес и вставляет устройство атомарно:
	// функция allocate получает занятые адреса и возвращает свободный.
	// Выбор адреса и вставка выполняются под блокировкой хранилища.
	CreateDeviceWithAddress(ctx context.Context, device *models.Device, allocate func(used []string) (string, error)) error
	GetDeviceForUser(ctx context.Context, id, userID string) (*models.Device, error)
	GetDevicesByUser(ctx context.Context, userID string) ([]models.Device, error)
	UpdateDeviceStatus(ctx context.Context, id, status string) error
	DeleteDevice(ctx context.Context, id string) error
	// SetDeviceCertSerial сохраняет серийный номер сертификата OpenVPN,
	// чтобы устройство можно было отозвать.
	SetDeviceCertSerial(ctx context.Context, id, serial string) error
}

type Manager struct {
	db          DeviceStore
	wgManager   *WireGuardManager
	ovpnManager *OpenVPNManager
	wgConfig    WireGuardConfig
	// box шифрует приватные ключи устройств перед записью в БД.
	// nil — шифрование не настроено, ключи хранятся как есть.
	box *secretbox.Box
}

func NewManager(db DeviceStore, wgConfig WireGuardConfig, ovpnConfig OpenVPNConfig) *Manager {
	return &Manager{
		db:          db,
		wgManager:   NewWireGuardManager(wgConfig),
		ovpnManager: NewOpenVPNManager(ovpnConfig),
		wgConfig:    wgConfig,
	}
}

// UseSecretBox включает шифрование приватных ключей устройств.
// Вызывается один раз при сборке сервиса, до обработки запросов.
func (m *Manager) UseSecretBox(box *secretbox.Box) {
	m.box = box
}

// sealKey шифрует приватный ключ для хранения; nil-шифр — ключ остаётся как есть.
func (m *Manager) sealKey(key string) (string, error) {
	if m.box == nil || key == "" {
		return key, nil
	}
	return m.box.Seal(key)
}

// openKey расшифровывает ключ из БД. Значения без метки шифрования
// возвращаются как есть — это записи, созданные до включения шифрования.
func (m *Manager) openKey(key string) (string, error) {
	if m.box == nil || key == "" {
		return key, nil
	}
	return m.box.Open(key)
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

	storedKey, err := m.sealKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("encrypt device key: %w", err)
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
		DeviceKey:  storedKey,
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
	// Выбор адреса выполняется внутри транзакции хранилища: список занятых
	// адресов и вставка защищены блокировкой, поэтому повторы не нужны.
	return m.db.CreateDeviceWithAddress(ctx, device, func(used []string) (string, error) {
		taken := make(map[string]struct{}, len(used))
		for _, address := range used {
			taken[address] = struct{}{}
		}
		return allocateIP(m.wgConfig.NetworkCIDR, taken)
	})
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
		privateKey, err := m.openKey(device.DeviceKey)
		if err != nil {
			return "", fmt.Errorf("decrypt device key: %w", err)
		}
		return m.wgManager.GetConfig(ClientConfig{
			PrivateKey: privateKey,
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
