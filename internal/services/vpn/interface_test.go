package vpn

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestEnsureInterfaceIsNoOpWhenDisabled(t *testing.T) {
	runner := &recordingRunner{}
	manager := enabledWireGuard(runner)
	manager.enabled = false

	if err := manager.EnsureInterface(context.Background()); err != nil {
		t.Fatalf("EnsureInterface: %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("при enabled=false команд быть не должно: %v", runner.calls)
	}
}

// Если интерфейс уже существует, поднимать его повторно не нужно.
func TestEnsureInterfaceKeepsExistingInterface(t *testing.T) {
	runner := &recordingRunner{}
	manager := enabledWireGuard(runner)
	ctx := context.Background()

	if err := manager.EnsureInterface(ctx); err != nil {
		t.Fatalf("первый вызов: %v", err)
	}
	if err := manager.EnsureInterface(ctx); err != nil {
		t.Fatalf("второй вызов: %v", err)
	}

	if len(runner.calls) != 1 {
		t.Fatalf("команд: %d, ожидалась одна проверка: %v", len(runner.calls), runner.calls)
	}
	if got := strings.Join(runner.calls[0], " "); got != "wg show wg0" {
		t.Fatalf("команда %q, ожидалась \"wg show wg0\"", got)
	}
}

// Отсутствующий интерфейс сервис поднимает сам: без этого `wg set` не работает.
func TestEnsureInterfaceBringsUpMissingInterface(t *testing.T) {
	runner := &recordingRunner{failOn: map[string]error{
		"wg show": errors.New("Unable to access interface: No such device"),
	}}
	manager := enabledWireGuard(runner)
	ctx := context.Background()

	if err := manager.EnsureInterface(ctx); err != nil {
		t.Fatalf("EnsureInterface: %v", err)
	}

	want := []string{"wg show wg0", "wg-quick up wg0"}
	if len(runner.calls) != len(want) {
		t.Fatalf("команд: %d, ожидалось %d: %v", len(runner.calls), len(want), runner.calls)
	}
	for i, command := range want {
		if got := strings.Join(runner.calls[i], " "); got != command {
			t.Fatalf("команда %d: %q, ожидалась %q", i, got, command)
		}
	}
}

// Ошибка подъёма не кэшируется: следующая попытка снова пробует поднять интерфейс.
func TestEnsureInterfaceDoesNotCacheFailure(t *testing.T) {
	runner := &recordingRunner{failOn: map[string]error{
		"wg show":     errors.New("No such device"),
		"wg-quick up": errors.New("Operation not permitted"),
	}}
	manager := enabledWireGuard(runner)
	ctx := context.Background()

	err := manager.EnsureInterface(ctx)
	if err == nil {
		t.Fatal("ожидалась ошибка подъёма интерфейса")
	}
	if !strings.Contains(err.Error(), "Operation not permitted") {
		t.Fatalf("потеряна причина: %v", err)
	}

	runner.failOn = nil
	if err := manager.EnsureInterface(ctx); err != nil {
		t.Fatalf("повторная попытка должна пройти: %v", err)
	}
}

// Устройство WireGuard не создаётся, если интерфейс поднять не удалось.
func TestCreateDeviceFailsWhenInterfaceCannotBeRaised(t *testing.T) {
	store := newMemStore()
	manager := newTestManager(store)
	manager.wgManager.enabled = true
	manager.wgManager.runner = &recordingRunner{failOn: map[string]error{
		"wg show":     errors.New("No such device"),
		"wg-quick up": errors.New("Operation not permitted"),
	}}

	_, err := manager.CreateDevice(context.Background(), "user-1", "laptop", ProtocolWireGuard)
	if !errors.Is(err, ErrWireGuardNotConfigured) {
		t.Fatalf("ожидалась ErrWireGuardNotConfigured, получено %v", err)
	}
	if len(store.devices) != 0 {
		t.Fatalf("устройство осталось в БД: %d", len(store.devices))
	}
}
