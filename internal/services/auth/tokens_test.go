package auth

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"vpn-service/internal/config"
)

type memStore struct {
	mu       sync.Mutex
	refresh  map[string]string
	revoked  map[string]time.Time
	failSave bool
}

func newMemStore() *memStore {
	return &memStore{
		refresh: make(map[string]string),
		revoked: make(map[string]time.Time),
	}
}

func (s *memStore) SaveRefreshToken(_ context.Context, hash, value string, _ time.Duration) error {
	if s.failSave {
		return errors.New("save failed")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh[hash] = value
	return nil
}

func (s *memStore) LoadRefreshToken(_ context.Context, hash string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.refresh[hash], nil
}

func (s *memStore) DeleteRefreshToken(_ context.Context, hash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.refresh, hash)
	return nil
}

func (s *memStore) RevokeAccessToken(_ context.Context, jti string, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revoked[jti] = time.Now().Add(ttl)
	return nil
}

func (s *memStore) IsAccessTokenRevoked(_ context.Context, jti string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.revoked[jti]
	return ok, nil
}

func testConfig() config.JWTConfig {
	return config.JWTConfig{
		Secret:            "test-secret",
		ExpireTime:        1,
		RefreshExpireTime: 24,
	}
}

func parseClaims(t *testing.T, token string) *Claims {
	t.Helper()

	claims := &Claims{}
	parsed, err := jwt.ParseWithClaims(token, claims, func(*jwt.Token) (interface{}, error) {
		return []byte("test-secret"), nil
	})
	if err != nil || !parsed.Valid {
		t.Fatalf("токен не разбирается: %v", err)
	}
	return claims
}

func TestIssueAccessToken(t *testing.T) {
	service := New(testConfig(), newMemStore())

	token, ttl, err := service.IssueAccessToken("user-1", "user@example.com")
	if err != nil {
		t.Fatalf("выпуск access-токена: %v", err)
	}
	if ttl != time.Hour {
		t.Fatalf("ttl=%v, ожидался час", ttl)
	}

	claims := parseClaims(t, token)
	if claims.UserID != "user-1" || claims.Email != "user@example.com" {
		t.Fatalf("claims не совпадают: %+v", claims)
	}
	if claims.Typ != TokenTypeAccess {
		t.Fatalf("typ=%q, ожидался %q", claims.Typ, TokenTypeAccess)
	}
	if claims.ID == "" {
		t.Fatal("jti пустой — отозвать такой токен невозможно")
	}
	if claims.ExpiresAt == nil || time.Until(claims.ExpiresAt.Time) > time.Hour {
		t.Fatal("срок жизни access-токена выставлен неверно")
	}
}

// Refresh-токен должен храниться только как хеш: утечка Redis не даёт
// возможности воспользоваться токенами.
func TestRefreshTokenIsStoredHashed(t *testing.T) {
	store := newMemStore()
	service := New(testConfig(), store)

	token, err := service.IssueRefreshToken(context.Background(), "user-1", "user@example.com")
	if err != nil {
		t.Fatalf("выпуск refresh-токена: %v", err)
	}
	if len(store.refresh) != 1 {
		t.Fatalf("записей в хранилище: %d, ожидалась 1", len(store.refresh))
	}

	for hash, value := range store.refresh {
		if hash == token {
			t.Fatal("refresh-токен сохранён в открытом виде как ключ")
		}
		if strings.Contains(value, token) {
			t.Fatal("refresh-токен попал в значение")
		}
		if len(hash) != 64 {
			t.Fatalf("длина хеша %d, ожидались 64 символа SHA-256", len(hash))
		}

		var record refreshRecord
		if err := json.Unmarshal([]byte(value), &record); err != nil {
			t.Fatalf("значение не JSON: %v", err)
		}
		if record.UserID != "user-1" || record.Email != "user@example.com" {
			t.Fatalf("в записи не те данные: %+v", record)
		}
	}
}

func TestRotateRefreshTokenIssuesNewPair(t *testing.T) {
	store := newMemStore()
	service := New(testConfig(), store)
	ctx := context.Background()

	refresh, err := service.IssueRefreshToken(ctx, "user-1", "user@example.com")
	if err != nil {
		t.Fatalf("выпуск: %v", err)
	}

	access, newRefresh, ttl, err := service.RotateRefreshToken(ctx, refresh)
	if err != nil {
		t.Fatalf("ротация: %v", err)
	}
	if ttl != time.Hour {
		t.Fatalf("ttl=%v, ожидался час", ttl)
	}
	if newRefresh == refresh {
		t.Fatal("refresh-токен не сменился")
	}
	if parseClaims(t, access).UserID != "user-1" {
		t.Fatal("новый access-токен выписан не тому пользователю")
	}

	if _, _, _, err := service.RotateRefreshToken(ctx, refresh); !errors.Is(err, ErrInvalidRefreshToken) {
		t.Fatalf("повторное использование старого токена: ожидалась ErrInvalidRefreshToken, получено %v", err)
	}
}

func TestRotateRejectsUnknownToken(t *testing.T) {
	service := New(testConfig(), newMemStore())

	if _, _, _, err := service.RotateRefreshToken(context.Background(), "unknown"); !errors.Is(err, ErrInvalidRefreshToken) {
		t.Fatalf("ожидалась ErrInvalidRefreshToken, получено %v", err)
	}
	if _, _, _, err := service.RotateRefreshToken(context.Background(), ""); !errors.Is(err, ErrInvalidRefreshToken) {
		t.Fatalf("пустой токен: ожидалась ErrInvalidRefreshToken, получено %v", err)
	}
}

func TestRevokeAccessTokenAddsToBlacklist(t *testing.T) {
	store := newMemStore()
	service := New(testConfig(), store)
	ctx := context.Background()

	token, _, err := service.IssueAccessToken("user-1", "user@example.com")
	if err != nil {
		t.Fatalf("выпуск: %v", err)
	}
	claims := parseClaims(t, token)

	if revoked, _ := service.IsAccessTokenRevoked(ctx, claims.ID); revoked {
		t.Fatal("токен отозван до logout")
	}

	if err := service.RevokeAccessToken(ctx, claims); err != nil {
		t.Fatalf("отзыв: %v", err)
	}

	revoked, err := service.IsAccessTokenRevoked(ctx, claims.ID)
	if err != nil {
		t.Fatalf("проверка отзыва: %v", err)
	}
	if !revoked {
		t.Fatal("токен не попал в блэклист")
	}
}

// Истёкший токен нет смысла заносить в блэклист: он уже невалиден.
func TestRevokeExpiredAccessTokenIsNoOp(t *testing.T) {
	store := newMemStore()
	service := New(testConfig(), store)

	claims := &Claims{
		UserID: "user-1",
		Typ:    TokenTypeAccess,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        "jti",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
		},
	}

	if err := service.RevokeAccessToken(context.Background(), claims); err != nil {
		t.Fatalf("отзыв: %v", err)
	}
	if len(store.revoked) != 0 {
		t.Fatalf("истёкший токен добавлен в блэклист: %v", store.revoked)
	}
}

func TestRevokeRefreshTokenRemovesRecord(t *testing.T) {
	store := newMemStore()
	service := New(testConfig(), store)
	ctx := context.Background()

	token, err := service.IssueRefreshToken(ctx, "user-1", "user@example.com")
	if err != nil {
		t.Fatalf("выпуск: %v", err)
	}

	if err := service.RevokeRefreshToken(ctx, token); err != nil {
		t.Fatalf("отзыв: %v", err)
	}
	if len(store.refresh) != 0 {
		t.Fatalf("запись осталась: %v", store.refresh)
	}
	if _, _, _, err := service.RotateRefreshToken(ctx, token); !errors.Is(err, ErrInvalidRefreshToken) {
		t.Fatalf("отозванный токен принят: %v", err)
	}
}

func TestDefaultTTLWhenConfigIsEmpty(t *testing.T) {
	service := New(config.JWTConfig{Secret: "secret"}, newMemStore())

	if service.AccessTTL() != time.Hour {
		t.Fatalf("AccessTTL=%v, ожидался час", service.AccessTTL())
	}
	if service.RefreshTTL() != 30*24*time.Hour {
		t.Fatalf("RefreshTTL=%v, ожидались 30 дней", service.RefreshTTL())
	}
}

func TestIssueRefreshTokenPropagatesStoreFailure(t *testing.T) {
	store := newMemStore()
	store.failSave = true
	service := New(testConfig(), store)

	if _, err := service.IssueRefreshToken(context.Background(), "user-1", "user@example.com"); err == nil {
		t.Fatal("ожидалась ошибка сохранения")
	}
}
