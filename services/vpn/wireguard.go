package vpn

import (
	"context"
	"fmt"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type WireGuardManager struct {
	client        *wgctrl.Client
	interfaceName string
	privateKey    string
	publicKey     string
	networkCIDR   string
}

func NewWireGuardManager(cfg WireGuardConfig) *WireGuardManager {
	client, err := wgctrl.New()
	if err != nil {
		// Если не удалось подключиться к WireGuard, используем nil (для тестирования)
		client = nil
	}

	return &WireGuardManager{
		client:        client,
		interfaceName: cfg.InterfaceName,
		privateKey:    cfg.PrivateKey,
		publicKey:     cfg.PublicKey,
		networkCIDR:   cfg.NetworkCIDR,
	}
}

func (m *WireGuardManager) AddPeer(ctx context.Context, deviceID, deviceKey string) error {
	if m.client == nil {
		// В продакшене нужно реальное подключение
		return fmt.Errorf("wireguard client not initialized")
	}

	// Получаем текущую конфигурацию
	dev, err := m.client.Device(m.interfaceName)
	if err != nil {
		return fmt.Errorf("failed to get device: %w", err)
	}

	// Генерируем приватный ключ для пира
	privateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}
	publicKey := privateKey.PublicKey()

	// Парсим CIDR
	allowedIPs := parseAllowedIPs(m.networkCIDR)

	// Создаем нового пира
	peerConfig := wgtypes.PeerConfig{
		PublicKey:                   publicKey,
		AllowedIPs:                  allowedIPs,
		PersistentKeepaliveInterval: 25,
	}

	// Сохраняем пира
	config := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peerConfig},
	}

	return m.client.ConfigureDevice(m.interfaceName, config)
}

func (m *WireGuardManager) RemovePeer(ctx context.Context, deviceID string) error {
	if m.client == nil {
		return fmt.Errorf("wireguard client not initialized")
	}

	// TODO: Реализовать удаление пира по его ключу
	// Для этого нужно найти пира в конфигурации и удалить
	return nil
}

func (m *WireGuardManager) GetConfig(deviceID, deviceKey string) (string, error) {
	// В реальном проекте здесь должна быть генерация полного конфига
	config := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = 10.0.0.2/32
DNS = 1.1.1.1, 8.8.8.8

[Peer]
PublicKey = %s
AllowedIPs = 0.0.0.0/0
Endpoint = vpn.example.com:51820
PersistentKeepalive = 25
`, deviceKey, m.publicKey)

	return config, nil
}

func parseAllowedIPs(cidr string) []wgtypes.IPNet {
	// Упрощенный парсинг
	parts := strings.Split(cidr, "/")
	if len(parts) != 2 {
		return nil
	}

	// В реальном проекте нужно нормально парсить IPNet
	return []wgtypes.IPNet{
		{
			IP:   []byte{10, 0, 0, 0},
			Mask: []byte{255, 255, 255, 0},
		},
	}
}
