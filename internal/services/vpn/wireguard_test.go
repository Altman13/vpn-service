package vpn

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type recordingRunner struct {
	calls  [][]string
	err    error
	failOn map[string]error
}

func (r *recordingRunner) Run(_ context.Context, name string, args ...string) error {
	call := append([]string{name}, args...)
	r.calls = append(r.calls, call)

	// failOn позволяет валить отдельную команду, например "wg set",
	// оставляя рабочими "wg show".
	if r.failOn != nil {
		key := name
		if len(args) > 0 {
			key = name + " " + args[0]
		}
		if err, ok := r.failOn[key]; ok {
			return err
		}
	}
	return r.err
}

func enabledWireGuard(runner CommandRunner) *WireGuardManager {
	manager := NewWireGuardManager(WireGuardConfig{
		InterfaceName: "wg0",
		Port:          51820,
		PublicKey:     "server-public-key",
		NetworkCIDR:   "10.0.0.0/24",
		Endpoint:      "vpn.example.com",
		DNS:           "1.1.1.1",
		AllowedIPs:    "0.0.0.0/0",
		Enabled:       true,
	})
	manager.runner = runner
	return manager
}

// Регрессия: AddPeer раньше возвращал nil, ничего не делая. Теперь пир
// действительно применяется к интерфейсу, и аргументы проверяемы.
func TestAddPeerAppliesAllowedIPs(t *testing.T) {
	runner := &recordingRunner{}
	manager := enabledWireGuard(runner)

	if err := manager.AddPeer(context.Background(), "peer-public-key", "10.0.0.2"); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}

	want := []string{"wg", "set", "wg0", "peer", "peer-public-key", "allowed-ips", "10.0.0.2/32"}
	if len(runner.calls) != 1 {
		t.Fatalf("вызовов: %d, ожидался 1", len(runner.calls))
	}
	if strings.Join(runner.calls[0], " ") != strings.Join(want, " ") {
		t.Fatalf("аргументы: %v, ожидались %v", runner.calls[0], want)
	}
}

func TestAddPeerIsNoOpWhenDisabled(t *testing.T) {
	runner := &recordingRunner{}
	manager := enabledWireGuard(runner)
	manager.enabled = false

	if err := manager.AddPeer(context.Background(), "peer-public-key", "10.0.0.2"); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("при enabled=false не должно быть вызовов, получено %v", runner.calls)
	}
}

func TestAddPeerRejectsInvalidInput(t *testing.T) {
	runner := &recordingRunner{}
	manager := enabledWireGuard(runner)

	if err := manager.AddPeer(context.Background(), "", "10.0.0.2"); err == nil {
		t.Fatal("ожидалась ошибка для пустого публичного ключа")
	}
	if err := manager.AddPeer(context.Background(), "peer-public-key", "не-адрес"); err == nil {
		t.Fatal("ожидалась ошибка для некорректного адреса")
	}
	if len(runner.calls) != 0 {
		t.Fatalf("wg не должен вызываться при ошибке валидации, получено %v", runner.calls)
	}
}

func TestAddPeerPropagatesCommandFailure(t *testing.T) {
	runner := &recordingRunner{err: errors.New("Operation not permitted")}
	manager := enabledWireGuard(runner)

	err := manager.AddPeer(context.Background(), "peer-public-key", "10.0.0.2")
	if err == nil {
		t.Fatal("ожидалась ошибка выполнения wg")
	}
	if !strings.Contains(err.Error(), "Operation not permitted") {
		t.Fatalf("потеряна причина ошибки: %v", err)
	}
}

func TestRemovePeerUsesStoredPublicKey(t *testing.T) {
	runner := &recordingRunner{}
	manager := enabledWireGuard(runner)

	if err := manager.RemovePeer(context.Background(), "peer-public-key"); err != nil {
		t.Fatalf("RemovePeer: %v", err)
	}

	want := []string{"wg", "set", "wg0", "peer", "peer-public-key", "remove"}
	if len(runner.calls) != 1 {
		t.Fatalf("вызовов: %d, ожидался 1", len(runner.calls))
	}
	if strings.Join(runner.calls[0], " ") != strings.Join(want, " ") {
		t.Fatalf("аргументы: %v, ожидались %v", runner.calls[0], want)
	}
}

func TestGetConfigUsesDeviceAddressAndEndpoint(t *testing.T) {
	manager := enabledWireGuard(&recordingRunner{})

	config, err := manager.GetConfig(ClientConfig{
		PrivateKey: "client-private-key",
		Address:    "10.0.0.7",
	})
	if err != nil {
		t.Fatalf("GetConfig: %v", err)
	}

	for _, want := range []string{
		"PrivateKey = client-private-key",
		"Address = 10.0.0.7/32",
		"DNS = 1.1.1.1",
		"PublicKey = server-public-key",
		"AllowedIPs = 0.0.0.0/0",
		"Endpoint = vpn.example.com:51820",
	} {
		if !strings.Contains(config, want) {
			t.Fatalf("в конфиге нет %q:\n%s", want, config)
		}
	}
	// Раньше адрес и сервер были захардкожены.
	if strings.Contains(config, "vpn.example.com:51820\nAddress = 10.0.0.2") ||
		strings.Contains(config, "10.0.0.2/32") {
		t.Fatalf("в конфиг попал захардкоженный адрес:\n%s", config)
	}
}

func TestGetConfigFailsWhenServerIsNotConfigured(t *testing.T) {
	cases := map[string]func(*WireGuardManager){
		"нет endpoint":         func(m *WireGuardManager) { m.endpoint = "" },
		"нет публичного ключа": func(m *WireGuardManager) { m.publicKey = "" },
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			manager := enabledWireGuard(&recordingRunner{})
			mutate(manager)

			_, err := manager.GetConfig(ClientConfig{PrivateKey: "key", Address: "10.0.0.2"})
			if !errors.Is(err, ErrWireGuardNotConfigured) {
				t.Fatalf("ожидалась ErrWireGuardNotConfigured, получено %v", err)
			}
		})
	}
}

func TestGetConfigRejectsDeviceWithoutAddress(t *testing.T) {
	manager := enabledWireGuard(&recordingRunner{})

	if _, err := manager.GetConfig(ClientConfig{PrivateKey: "key", Address: ""}); err == nil {
		t.Fatal("ожидалась ошибка для устройства без адреса")
	}
}
