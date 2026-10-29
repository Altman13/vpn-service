package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"vpn-service/internal/api/middleware"
	"vpn-service/internal/config"
	"vpn-service/internal/services/auth"
	"vpn-service/pkg/logger"
)

// memTokenStore — хранилище refresh-токенов и блэклиста в памяти.
type memTokenStore struct {
	mu      sync.Mutex
	refresh map[string]string
	revoked map[string]struct{}
}

func newMemTokenStore() *memTokenStore {
	return &memTokenStore{
		refresh: make(map[string]string),
		revoked: make(map[string]struct{}),
	}
}

func (s *memTokenStore) SaveRefreshToken(_ context.Context, hash, value string, _ time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh[hash] = value
	return nil
}

func (s *memTokenStore) LoadRefreshToken(_ context.Context, hash string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.refresh[hash], nil
}

func (s *memTokenStore) DeleteRefreshToken(_ context.Context, hash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.refresh, hash)
	return nil
}

func (s *memTokenStore) RevokeAccessToken(_ context.Context, jti string, _ time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revoked[jti] = struct{}{}
	return nil
}

func (s *memTokenStore) IsAccessTokenRevoked(_ context.Context, jti string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.revoked[jti]
	return ok, nil
}

func newAuthRouter(t *testing.T) (*gin.Engine, *auth.Service) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	jwtConfig := config.JWTConfig{Secret: testSecret, ExpireTime: 1, RefreshExpireTime: 24}
	service := auth.New(jwtConfig, newMemTokenStore())
	handler := NewAuthHandler(service, nil, logger.New("error"))

	router := gin.New()
	router.POST("/api/v1/auth/refresh", handler.RefreshToken)

	protected := router.Group("/api/v1")
	protected.Use(middleware.Auth(jwtConfig, middleware.AuthDeps{Revocation: service}))
	protected.POST("/auth/logout", handler.Logout)
	protected.GET("/vpn/devices", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	return router, service
}

func issuePair(t *testing.T, service *auth.Service) (access, refresh string) {
	t.Helper()

	access, _, err := service.IssueAccessToken(ownerID, "user@example.com")
	if err != nil {
		t.Fatalf("выпуск access-токена: %v", err)
	}
	refresh, err = service.IssueRefreshToken(context.Background(), ownerID, "user@example.com")
	if err != nil {
		t.Fatalf("выпуск refresh-токена: %v", err)
	}
	return access, refresh
}

func postJSON(t *testing.T, router *gin.Engine, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()

	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(payload)))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	return recorder
}

func TestRefreshEndpointReturnsNewPairAndConsumesOldToken(t *testing.T) {
	router, service := newAuthRouter(t)
	_, refresh := issuePair(t, service)

	recorder := postJSON(t, router, "/api/v1/auth/refresh", "", map[string]string{"refresh_token": refresh})
	if recorder.Code != http.StatusOK {
		t.Fatalf("ожидался 200, получен %d (%s)", recorder.Code, recorder.Body.String())
	}

	var response struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if response.AccessToken == "" || response.RefreshToken == "" {
		t.Fatalf("не выдана пара токенов: %s", recorder.Body.String())
	}
	if response.RefreshToken == refresh {
		t.Fatal("refresh-токен не сменился")
	}
	if response.TokenType != "Bearer" || response.ExpiresIn <= 0 {
		t.Fatalf("некорректные метаданные: %+v", response)
	}

	// Старый refresh-токен должен быть погашен.
	repeat := postJSON(t, router, "/api/v1/auth/refresh", "", map[string]string{"refresh_token": refresh})
	if repeat.Code != http.StatusUnauthorized {
		t.Fatalf("повторное использование старого токена: получен %d (%s)", repeat.Code, repeat.Body.String())
	}
}

func TestRefreshEndpointRejectsGarbage(t *testing.T) {
	router, _ := newAuthRouter(t)

	cases := []struct {
		name string
		body map[string]string
		want int
	}{
		// Отсутствие поля — ошибка запроса, а не попытка входа.
		{"пустое тело", map[string]string{}, http.StatusBadRequest},
		{"мусорный токен", map[string]string{"refresh_token": "not-a-token"}, http.StatusUnauthorized},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			recorder := postJSON(t, router, "/api/v1/auth/refresh", "", tc.body)
			if recorder.Code != tc.want {
				t.Fatalf("получен %d, ожидался %d (%s)", recorder.Code, tc.want, recorder.Body.String())
			}
		})
	}
}

func TestLogoutRevokesAccessAndRefreshTokens(t *testing.T) {
	router, service := newAuthRouter(t)
	access, refresh := issuePair(t, service)

	// До logout токен работает.
	before := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/vpn/devices", nil)
	req.Header.Set("Authorization", "Bearer "+access)
	router.ServeHTTP(before, req)
	if before.Code != http.StatusOK {
		t.Fatalf("до logout: получен %d", before.Code)
	}

	logout := postJSON(t, router, "/api/v1/auth/logout", access, map[string]string{"refresh_token": refresh})
	if logout.Code != http.StatusOK {
		t.Fatalf("logout: получен %d (%s)", logout.Code, logout.Body.String())
	}

	after := httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/v1/vpn/devices", nil)
	req.Header.Set("Authorization", "Bearer "+access)
	router.ServeHTTP(after, req)
	if after.Code != http.StatusUnauthorized {
		t.Fatalf("после logout access-токен работает: получен %d (%s)", after.Code, after.Body.String())
	}

	refreshAttempt := postJSON(t, router, "/api/v1/auth/refresh", "", map[string]string{"refresh_token": refresh})
	if refreshAttempt.Code != http.StatusUnauthorized {
		t.Fatalf("после logout refresh-токен работает: получен %d", refreshAttempt.Code)
	}
}

func TestLogoutRequiresAuthentication(t *testing.T) {
	router, _ := newAuthRouter(t)

	recorder := postJSON(t, router, "/api/v1/auth/logout", "", map[string]string{})
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("ожидался 401, получен %d (%s)", recorder.Code, recorder.Body.String())
	}
}
