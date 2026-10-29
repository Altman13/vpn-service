//go:build integration

// Интеграционные тесты требуют живой PostgreSQL со применёнными миграциями:
//
//	TEST_DATABASE_DSN='postgres://postgres:postgres@127.0.0.1:15432/vpn_service?sslmode=disable' \
//	  go test -tags integration -run Integration -v ./internal/services/vpn/
package vpn

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"

	"vpn-service/internal/storage/postgres"
)

const integrationUserID = "22222222-2222-2222-2222-222222222222"

func integrationStore(t *testing.T) *postgres.DB {
	t.Helper()

	dsn := os.Getenv("TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("TEST_DATABASE_DSN не задан — интеграционный тест пропущен")
	}

	db, err := postgres.NewWithDSN(dsn)
	if err != nil {
		t.Fatalf("подключение к тестовой БД: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func integrationUser(t *testing.T, db *postgres.DB) string {
	t.Helper()

	_, err := db.ExecContext(context.Background(),
		`INSERT INTO users (id, email, password_hash, full_name)
		 VALUES ($1, 'integration@example.com', 'hash', 'Integration')
		 ON CONFLICT (id) DO NOTHING`, integrationUserID)
	if err != nil {
		t.Fatalf("создание пользователя: %v", err)
	}

	// Чистим устройства прошлых запусков, иначе адреса уже заняты.
	if _, err := db.ExecContext(context.Background(),
		`DELETE FROM devices WHERE user_id = $1`, integrationUserID); err != nil {
		t.Fatalf("очистка устройств: %v", err)
	}
	return integrationUserID
}

// Конкурентная выдача адресов: без advisory-блокировки параллельные запросы
// выбирают одинаковый свободный адрес, и часть из них падает на уникальном
// индексе. Тест проверяет, что этого не происходит и адреса не повторяются.
func TestIntegrationConcurrentDeviceCreation(t *testing.T) {
	db := integrationStore(t)
	ctx := context.Background()
	userID := integrationUser(t, db)

	manager := NewManager(db, WireGuardConfig{
		InterfaceName: "wg0",
		Port:          51820,
		PublicKey:     "server-public-key",
		NetworkCIDR:   "10.0.0.0/24",
		Endpoint:      "vpn.test",
	}, OpenVPNConfig{})

	const workers = 12

	var wg sync.WaitGroup
	errs := make(chan error, workers)
	addresses := make(chan string, workers)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()

			device, err := manager.CreateDevice(ctx, userID, fmt.Sprintf("device-%d", n), ProtocolWireGuard)
			if err != nil {
				errs <- err
				return
			}
			addresses <- device.IPAddress
		}(i)
	}

	wg.Wait()
	close(errs)
	close(addresses)

	for err := range errs {
		t.Fatalf("параллельное создание устройства завершилось ошибкой: %v", err)
	}

	seen := make(map[string]struct{}, workers)
	for address := range addresses {
		if _, duplicate := seen[address]; duplicate {
			t.Fatalf("адрес выдан дважды: %s", address)
		}
		seen[address] = struct{}{}
	}

	if len(seen) != workers {
		t.Fatalf("уникальных адресов %d, ожидалось %d", len(seen), workers)
	}

	var stored int
	if err := db.GetContext(ctx, &stored,
		`SELECT count(*) FROM devices WHERE user_id = $1`, userID); err != nil {
		t.Fatalf("подсчёт устройств: %v", err)
	}
	if stored != workers {
		t.Fatalf("в БД %d устройств, ожидалось %d", stored, workers)
	}

	// Отзыв освобождает адрес: частичный уникальный индекс это разрешает.
	if err := manager.RevokeDevice(ctx, userID, "nonexistent"); err == nil {
		t.Fatal("отзыв несуществующего устройства должен возвращать ошибку")
	}
}
