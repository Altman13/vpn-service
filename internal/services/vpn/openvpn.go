package vpn

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

type OpenVPNManager struct {
	enabled     bool
	pkiDir      string
	endpoint    string
	proto       string
	port        int
	networkCIDR string
	certTTL     time.Duration

	// CA грузится лениво: если протокол выключен, каталог PKI даже не читается.
	once    sync.Once
	pki     *PKI
	initErr error
}

func NewOpenVPNManager(cfg OpenVPNConfig) *OpenVPNManager {
	proto := cfg.Proto
	if proto == "" {
		proto = "udp"
	}

	return &OpenVPNManager{
		enabled:     cfg.Enabled,
		pkiDir:      cfg.PKIDir,
		endpoint:    cfg.Endpoint,
		proto:       proto,
		port:        cfg.Port,
		networkCIDR: cfg.NetworkCIDR,
	}
}

// authority возвращает CA или объясняет, почему протокол недоступен.
func (m *OpenVPNManager) authority() (*PKI, error) {
	if !m.enabled {
		return nil, fmt.Errorf("%w: vpn.openvpn.enabled is false", ErrOpenVPNNotConfigured)
	}

	m.once.Do(func() {
		m.pki, m.initErr = LoadOrCreatePKI(m.pkiDir)
	})
	if m.initErr != nil {
		return nil, fmt.Errorf("%w: %v", ErrOpenVPNNotConfigured, m.initErr)
	}
	return m.pki, nil
}

// AddClient проверяет, что PKI готова: сертификат выпускается при выдаче
// конфига, поэтому устройство можно создать заранее.
func (m *OpenVPNManager) AddClient(ctx context.Context, deviceID string) error {
	_, err := m.authority()
	return err
}

// IssueConfig выпускает новый клиентский сертификат и собирает .ovpn.
// Возвращается серийный номер: его нужно сохранить, чтобы сертификат
// можно было отозвать.
func (m *OpenVPNManager) IssueConfig(ctx context.Context, deviceID string) (string, string, error) {
	pki, err := m.authority()
	if err != nil {
		return "", "", err
	}
	if strings.TrimSpace(m.endpoint) == "" {
		return "", "", fmt.Errorf("%w: endpoint is empty", ErrOpenVPNNotConfigured)
	}
	if m.port <= 0 {
		return "", "", fmt.Errorf("%w: port is not configured", ErrOpenVPNNotConfigured)
	}

	certPEM, keyPEM, serial, err := pki.IssueClient(deviceID, m.certTTL)
	if err != nil {
		return "", "", err
	}

	var builder strings.Builder
	fmt.Fprintf(&builder, "client\ndev tun\nproto %s\nremote %s %d\n", m.proto, m.endpoint, m.port)
	builder.WriteString("resolv-retry infinite\nnobind\npersist-key\npersist-tun\n")
	builder.WriteString("remote-cert-tls server\nauth SHA256\nverb 3\n")
	fmt.Fprintf(&builder, "\n<ca>\n%s</ca>\n", certPEMBlock(pki.CAPEM()))
	fmt.Fprintf(&builder, "\n<cert>\n%s</cert>\n", certPEMBlock(certPEM))
	fmt.Fprintf(&builder, "\n<key>\n%s</key>\n", certPEMBlock(keyPEM))

	return builder.String(), serial, nil
}

// Revoke заносит сертификат устройства в CRL.
func (m *OpenVPNManager) Revoke(serial string) error {
	pki, err := m.authority()
	if err != nil {
		return err
	}
	return pki.Revoke(serial)
}

// certPEMBlock убирает заголовок и подвал PEM-блока: внутри <cert>/<key>
// OpenVPN ожидает только тело в base64.
func certPEMBlock(pemBytes []byte) string {
	lines := strings.Split(strings.TrimSpace(string(pemBytes)), "\n")
	var body []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "-----") {
			continue
		}
		body = append(body, line)
	}
	return strings.Join(body, "\n")
}
