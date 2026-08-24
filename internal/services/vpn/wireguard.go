package vpn

import (
	"context"
	"fmt"
)

type WireGuardManager struct {
	interfaceName string
	privateKey    string
	publicKey     string
	networkCIDR   string
}

func NewWireGuardManager(cfg WireGuardConfig) *WireGuardManager {
	return &WireGuardManager{
		interfaceName: cfg.InterfaceName,
		privateKey:    cfg.PrivateKey,
		publicKey:     cfg.PublicKey,
		networkCIDR:   cfg.NetworkCIDR,
	}
}

func (m *WireGuardManager) AddPeer(ctx context.Context, deviceID, deviceKey string) error {
	// В реальном проекте здесь была бы интеграция с WireGuard
	// Сейчас возвращаем nil для тестирования
	return nil
}

func (m *WireGuardManager) RemovePeer(ctx context.Context, deviceID string) error {
	return nil
}

func (m *WireGuardManager) GetConfig(deviceID, deviceKey string) (string, error) {
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
