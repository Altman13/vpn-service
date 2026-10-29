package handlers

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"vpn-service/internal/api/middleware"
	"vpn-service/internal/config"
	"vpn-service/internal/services/auth"
	"vpn-service/internal/services/vpn"
	"vpn-service/internal/storage/models"
	"vpn-service/pkg/logger"
)

const (
	testSecret = "test-jwt-secret"
	ownerID    = "11111111-1111-1111-1111-111111111111"
	otherID    = "22222222-2222-2222-2222-222222222222"
	ownerKey   = "owner-private-key"
)

// fakeDeviceStore повторяет семантику SQL-хранилища: GetDeviceForUser
// возвращает sql.ErrNoRows, если устройство принадлежит другому пользователю.
type fakeDeviceStore struct {
	mu      sync.Mutex
	devices map[string]*models.Device
}

func newFakeDeviceStore() *fakeDeviceStore {
	return &fakeDeviceStore{devices: make(map[string]*models.Device)}
}

func (s *fakeDeviceStore) seed(device *models.Device) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.devices[device.ID] = device
}

func (s *fakeDeviceStore) CreateDeviceWithAddress(_ context.Context, device *models.Device, allocate func(used []string) (string, error)) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	used := make([]string, 0, len(s.devices))
	for _, existing := range s.devices {
		if existing.Status != "revoked" && existing.IPAddress != "" {
			used = append(used, existing.IPAddress)
		}
	}

	address, err := allocate(used)
	if err != nil {
		return err
	}
	device.IPAddress = address
	s.devices[device.ID] = device
	return nil
}

func (s *fakeDeviceStore) GetDeviceForUser(_ context.Context, id, userID string) (*models.Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	device, ok := s.devices[id]
	if !ok || device.UserID != userID {
		return nil, sql.ErrNoRows
	}
	return device, nil
}

func (s *fakeDeviceStore) GetDevicesByUser(_ context.Context, userID string) ([]models.Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]models.Device, 0)
	for _, device := range s.devices {
		if device.UserID == userID {
			result = append(result, *device)
		}
	}
	return result, nil
}

func (s *fakeDeviceStore) UpdateDeviceStatus(_ context.Context, id, status string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if device, ok := s.devices[id]; ok {
		device.Status = status
	}
	return nil
}

func (s *fakeDeviceStore) DeleteDevice(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.devices, id)
	return nil
}

func (s *fakeDeviceStore) SetDeviceKey(_ context.Context, id, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if device, ok := s.devices[id]; ok {
		device.DeviceKey = key
	}
	return nil
}

func (s *fakeDeviceStore) SetDeviceCertSerial(_ context.Context, id, serial string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if device, ok := s.devices[id]; ok {
		device.CertSerial = serial
	}
	return nil
}

func tokenFor(t *testing.T, userID string) string {
	t.Helper()
	claims := middleware.Claims{
		UserID: userID,
		Email:  "user@example.com",
		Typ:    auth.TokenTypeAccess,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(testSecret))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return signed
}

func newTestRouter(store vpn.DeviceStore) *gin.Engine {
	gin.SetMode(gin.TestMode)

	jwtConfig := config.JWTConfig{Secret: testSecret, ExpireTime: 1}
	manager := vpn.NewManager(store,
		vpn.WireGuardConfig{
			PublicKey:   "server-public-key",
			NetworkCIDR: "10.0.0.0/24",
			Endpoint:    "vpn.test",
			Port:        51820,
			DNS:         "1.1.1.1",
			AllowedIPs:  "0.0.0.0/0",
		},
		vpn.OpenVPNConfig{Port: 1194},
	)
	handler := NewVPNHandler(logger.New("error"), manager)

	router := gin.New()
	protected := router.Group("/api/v1")
	protected.Use(middleware.Auth(jwtConfig, middleware.AuthDeps{}))
	protected.POST("/vpn/devices", handler.CreateDevice)
	protected.GET("/vpn/devices", handler.GetDevices)
	protected.GET("/vpn/devices/:id/config", handler.GetDeviceConfig)
	protected.DELETE("/vpn/devices/:id", handler.RevokeDevice)
	return router
}

func call(t *testing.T, router *gin.Engine, method, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()

	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			t.Fatalf("marshal body: %v", err)
		}
	}

	req := httptest.NewRequest(method, path, bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	return recorder
}

func otherUsersDevice() *models.Device {
	return &models.Device{
		ID:        "dev-owned-by-other",
		UserID:    otherID,
		Name:      "MacBook",
		Protocol:  vpn.ProtocolWireGuard,
		DeviceKey: ownerKey,
		PublicKey: "peer-public-key",
		IPAddress: "10.0.0.2",
		Status:    "active",
	}
}

// Регрессия P0: чужой конфиг не отдаётся, даже если id устройства известен.
func TestGetDeviceConfigDoesNotLeakOtherUsersDevice(t *testing.T) {
	store := newFakeDeviceStore()
	store.seed(otherUsersDevice())
	router := newTestRouter(store)
	token := tokenFor(t, ownerID)

	recorder := call(t, router, http.MethodGet, "/api/v1/vpn/devices/dev-owned-by-other/config", token, nil)

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("ожидался 404, получен %d (%s)", recorder.Code, recorder.Body.String())
	}
	if bytes.Contains(recorder.Body.Bytes(), []byte(ownerKey)) {
		t.Fatalf("в ответе утёк приватный ключ чужого устройства: %s", recorder.Body.String())
	}
}

func TestGetDeviceConfigReturnsOwnDevice(t *testing.T) {
	store := newFakeDeviceStore()
	own := otherUsersDevice()
	own.UserID = ownerID
	store.seed(own)
	router := newTestRouter(store)

	recorder := call(t, router, http.MethodGet, "/api/v1/vpn/devices/dev-owned-by-other/config", tokenFor(t, ownerID), nil)

	if recorder.Code != http.StatusOK {
		t.Fatalf("ожидался 200, получен %d (%s)", recorder.Code, recorder.Body.String())
	}
	if !bytes.Contains(recorder.Body.Bytes(), []byte(ownerKey)) {
		t.Fatalf("конфиг владельца не содержит ключ устройства: %s", recorder.Body.String())
	}
}

func TestGetDevicesReturnsOnlyOwnDevices(t *testing.T) {
	store := newFakeDeviceStore()
	store.seed(otherUsersDevice())

	own := otherUsersDevice()
	own.ID = "dev-owned-by-owner"
	own.UserID = ownerID
	store.seed(own)

	router := newTestRouter(store)
	recorder := call(t, router, http.MethodGet, "/api/v1/vpn/devices?user_id="+otherID, tokenFor(t, ownerID), nil)

	if recorder.Code != http.StatusOK {
		t.Fatalf("ожидался 200, получен %d (%s)", recorder.Code, recorder.Body.String())
	}

	var devices []models.Device
	if err := json.Unmarshal(recorder.Body.Bytes(), &devices); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(devices) != 1 || devices[0].ID != "dev-owned-by-owner" {
		t.Fatalf("возвращены не только свои устройства: %s", recorder.Body.String())
	}
}

// Регрессия P0: user_id из тела запроса игнорируется, владелец берётся из JWT.
func TestCreateDeviceIgnoresUserIDFromBody(t *testing.T) {
	store := newFakeDeviceStore()
	router := newTestRouter(store)

	body := map[string]string{
		"device_name": "My Laptop",
		"protocol":    "wireguard",
		"user_id":     otherID, // попытка создать устройство на чужой аккаунт
	}
	recorder := call(t, router, http.MethodPost, "/api/v1/vpn/devices", tokenFor(t, ownerID), body)

	if recorder.Code != http.StatusCreated {
		t.Fatalf("ожидался 201, получен %d (%s)", recorder.Code, recorder.Body.String())
	}

	var created models.Device
	if err := json.Unmarshal(recorder.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if created.UserID != ownerID {
		t.Fatalf("устройство создано на user_id %q, ожидался владелец из токена %q", created.UserID, ownerID)
	}
}

func TestRevokeDeviceRejectsOtherUsersDevice(t *testing.T) {
	store := newFakeDeviceStore()
	store.seed(otherUsersDevice())
	router := newTestRouter(store)

	recorder := call(t, router, http.MethodDelete, "/api/v1/vpn/devices/dev-owned-by-other", tokenFor(t, ownerID), nil)

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("ожидался 404, получен %d (%s)", recorder.Code, recorder.Body.String())
	}

	saved, err := store.GetDeviceForUser(context.Background(), "dev-owned-by-other", otherID)
	if err != nil {
		t.Fatalf("устройство жертвы пропало из хранилища: %v", err)
	}
	if saved.Status != "active" {
		t.Fatalf("чужое устройство изменено, статус: %s", saved.Status)
	}
}

func TestCreateDeviceRejectsUnsupportedProtocol(t *testing.T) {
	router := newTestRouter(newFakeDeviceStore())
	body := map[string]string{"device_name": "Laptop", "protocol": "pptp"}
	recorder := call(t, router, http.MethodPost, "/api/v1/vpn/devices", tokenFor(t, ownerID), body)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("ожидался 400, получен %d (%s)", recorder.Code, recorder.Body.String())
	}
}

func TestUnauthenticatedRequestIsRejected(t *testing.T) {
	router := newTestRouter(newFakeDeviceStore())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/vpn/devices", nil)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("ожидался 401, получен %d (%s)", recorder.Code, recorder.Body.String())
	}
}

// Ненастроенный провайдер — это состояние сервера, а не ошибка клиента,
// поэтому 503, а не 400/500.
func TestCreateDeviceReturns503WhenProviderIsNotConfigured(t *testing.T) {
	router := newTestRouter(newFakeDeviceStore())

	body := map[string]string{"device_name": "Laptop", "protocol": "openvpn"}
	recorder := call(t, router, http.MethodPost, "/api/v1/vpn/devices", tokenFor(t, ownerID), body)

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("ожидался 503, получен %d (%s)", recorder.Code, recorder.Body.String())
	}
}
