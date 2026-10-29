package vpn

import (
	"context"
	"fmt"
)

type OpenVPNManager struct {
	configPath  string
	port        int
	networkCIDR string
}

func NewOpenVPNManager(cfg OpenVPNConfig) *OpenVPNManager {
	return &OpenVPNManager{
		configPath:  cfg.ConfigPath,
		port:        cfg.Port,
		networkCIDR: cfg.NetworkCIDR,
	}
}

// AddClient, RemoveClient и GetConfig намеренно завершаются ошибкой, а не
// тихо возвращают nil. Раньше создание устройства OpenVPN «проходило
// успешно», хотя никакого клиента не появлялось, а в конфиг подставлялись
// заглушки YOUR_CA_CERT_HERE. Чтобы включить протокол, нужно подключить PKI
// (CA, выпуск и отзыв сертификатов) — без него устройство нерабочее,
// и честнее сказать об этом сразу.
func (m *OpenVPNManager) AddClient(ctx context.Context, deviceID, deviceKey string) error {
	return fmt.Errorf("%w: выдача сертификатов OpenVPN не реализована", ErrOpenVPNNotConfigured)
}

func (m *OpenVPNManager) RemoveClient(ctx context.Context, deviceID string) error {
	return fmt.Errorf("%w: выдача сертификатов OpenVPN не реализована", ErrOpenVPNNotConfigured)
}

func (m *OpenVPNManager) GetConfig(deviceID, deviceKey string) (string, error) {
	return "", fmt.Errorf("%w: выдача сертификатов OpenVPN не реализована", ErrOpenVPNNotConfigured)
}
