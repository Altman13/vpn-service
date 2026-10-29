package vpn

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"
)

// CommandRunner выполняет внешние команды. Вынесен в интерфейс, чтобы
// проверять формируемые аргументы в тестах без запуска wg.
type CommandRunner interface {
	Run(ctx context.Context, name string, args ...string) error
}

type execRunner struct{}

func (execRunner) Run(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return nil
}

// ClientConfig — всё, что нужно клиенту для подключения.
// Параметры сервера (публичный ключ, endpoint, DNS, AllowedIPs) берутся из
// WireGuardConfig: держать их ещё и здесь значило бы иметь два источника
// истины, которые могут разойтись.
type ClientConfig struct {
	PrivateKey string
	Address    string
}

type WireGuardManager struct {
	interfaceName string
	publicKey     string
	networkCIDR   string
	endpoint      string
	dns           string
	allowedIPs    string
	port          int
	enabled       bool
	runner        CommandRunner

	mu         sync.Mutex
	ifaceReady bool
}

func NewWireGuardManager(cfg WireGuardConfig) *WireGuardManager {
	allowedIPs := cfg.AllowedIPs
	if allowedIPs == "" {
		allowedIPs = "0.0.0.0/0"
	}

	return &WireGuardManager{
		interfaceName: cfg.InterfaceName,
		publicKey:     cfg.PublicKey,
		networkCIDR:   cfg.NetworkCIDR,
		endpoint:      cfg.Endpoint,
		dns:           cfg.DNS,
		allowedIPs:    allowedIPs,
		port:          cfg.Port,
		enabled:       cfg.Enabled,
		runner:        execRunner{},
	}
}

// EnsureInterface гарантирует, что интерфейс wg существует.
//
// `wg set` работает только с уже поднятым интерфейсом, поэтому при
// enabled=true сервис сам поднимает его через `wg-quick up`, если wg его не
// видит. Результат запоминается: повторно команды не выполняются, но ошибка
// не кэшируется — следующая попытка снова проверит интерфейс.
func (m *WireGuardManager) EnsureInterface(ctx context.Context) error {
	if !m.enabled {
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.ifaceReady {
		return nil
	}

	if err := m.runner.Run(ctx, "wg", "show", m.interfaceName); err == nil {
		m.ifaceReady = true
		return nil
	}

	if err := m.runner.Run(ctx, "wg-quick", "up", m.interfaceName); err != nil {
		return fmt.Errorf("bring up wireguard interface %q: %w", m.interfaceName, err)
	}
	m.ifaceReady = true
	return nil
}

// AddPeer применяет пира к интерфейсу через wg.
// При enabled=false пир не применяется: сервис работает в режиме выдачи
// конфигов, а интерфейсом управляют внешние инструменты.
func (m *WireGuardManager) AddPeer(ctx context.Context, publicKey, address string) error {
	if !m.enabled {
		return nil
	}
	if publicKey == "" {
		return fmt.Errorf("%w: empty peer public key", ErrWireGuardNotConfigured)
	}
	if net.ParseIP(address) == nil {
		return fmt.Errorf("invalid peer address %q", address)
	}

	args := []string{
		"set", m.interfaceName,
		"peer", publicKey,
		"allowed-ips", address + "/32",
	}
	if err := m.runner.Run(ctx, "wg", args...); err != nil {
		return fmt.Errorf("add wireguard peer: %w", err)
	}
	return nil
}

func (m *WireGuardManager) RemovePeer(ctx context.Context, publicKey string) error {
	if !m.enabled {
		return nil
	}
	if publicKey == "" {
		return fmt.Errorf("%w: empty peer public key", ErrWireGuardNotConfigured)
	}

	args := []string{"set", m.interfaceName, "peer", publicKey, "remove"}
	if err := m.runner.Run(ctx, "wg", args...); err != nil {
		return fmt.Errorf("remove wireguard peer: %w", err)
	}
	return nil
}

// GetConfig собирает клиентский конфиг из параметров сервера и данных
// устройства. Если чего-то не хватает, возвращается ошибка: раньше в конфиг
// молча подставлялись захардкоженные 10.0.0.2 и vpn.example.com.
func (m *WireGuardManager) GetConfig(cfg ClientConfig) (string, error) {
	if cfg.PrivateKey == "" {
		return "", fmt.Errorf("%w: device has no wireguard key", ErrWireGuardNotConfigured)
	}
	if m.publicKey == "" {
		return "", fmt.Errorf("%w: server public key is empty", ErrWireGuardNotConfigured)
	}
	if m.endpoint == "" {
		return "", fmt.Errorf("%w: endpoint host is empty", ErrWireGuardNotConfigured)
	}
	if net.ParseIP(cfg.Address) == nil {
		return "", fmt.Errorf("%w: device has no valid address", ErrWireGuardNotConfigured)
	}

	var builder strings.Builder
	builder.WriteString("[Interface]\n")
	fmt.Fprintf(&builder, "PrivateKey = %s\n", cfg.PrivateKey)
	fmt.Fprintf(&builder, "Address = %s/32\n", cfg.Address)
	if m.dns != "" {
		fmt.Fprintf(&builder, "DNS = %s\n", m.dns)
	}
	builder.WriteString("\n[Peer]\n")
	fmt.Fprintf(&builder, "PublicKey = %s\n", m.publicKey)
	fmt.Fprintf(&builder, "AllowedIPs = %s\n", m.allowedIPs)
	fmt.Fprintf(&builder, "Endpoint = %s\n", net.JoinHostPort(m.endpoint, strconv.Itoa(m.port)))
	builder.WriteString("PersistentKeepalive = 25\n")

	return builder.String(), nil
}
