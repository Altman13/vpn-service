package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"

	"vpn-service/internal/api/middleware"
	"vpn-service/internal/config"
	"vpn-service/internal/services/auth"
	"vpn-service/internal/storage/models"
	"vpn-service/internal/storage/postgres"
	"vpn-service/pkg/logger"
)

// fakeUserStore повторяет семантику SQL-хранилища: sql.ErrNoRows при
// отсутствии записи и ErrDuplicateEmail при занятом адресе.
type fakeUserStore struct {
	mu    sync.Mutex
	users map[string]*models.User
}

func newFakeUserStore() *fakeUserStore {
	return &fakeUserStore{users: make(map[string]*models.User)}
}

func (s *fakeUserStore) CreateUser(_ context.Context, user *models.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, existing := range s.users {
		if existing.Email == user.Email {
			return postgres.ErrDuplicateEmail
		}
	}
	copied := *user
	s.users[user.ID] = &copied
	return nil
}

func (s *fakeUserStore) GetUser(_ context.Context, id string) (*models.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	user, ok := s.users[id]
	if !ok {
		return nil, sql.ErrNoRows
	}
	return user, nil
}

func (s *fakeUserStore) GetUserByEmail(_ context.Context, email string) (*models.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, user := range s.users {
		if user.Email == email {
			return user, nil
		}
	}
	return nil, sql.ErrNoRows
}

func (s *fakeUserStore) UpdateUser(_ context.Context, id, fullName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	user, ok := s.users[id]
	if !ok {
		return sql.ErrNoRows
	}
	user.FullName = fullName
	return nil
}

// fakeStatusAdapter даёт middleware проверку статуса поверх того же хранилища.
type fakeStatusAdapter struct {
	store *fakeUserStore
}

func (f fakeStatusAdapter) GetUserStatus(ctx context.Context, id string) (string, error) {
	user, err := f.store.GetUser(ctx, id)
	if err != nil {
		return "", err
	}
	return user.Status, nil
}

const testUserID = "11111111-1111-1111-1111-111111111111"

func newAuthTestRouter(t *testing.T, store *fakeUserStore) (*gin.Engine, *auth.Service) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	jwtConfig := config.JWTConfig{Secret: testSecret, ExpireTime: 1, RefreshExpireTime: 24}
	service := auth.New(jwtConfig, newMemTokenStore())
	handler := NewAuthHandler(service, store, logger.New("error"))

	router := gin.New()
	router.POST("/api/v1/auth/register", handler.Register)
	router.POST("/api/v1/auth/login", handler.Login)

	protected := router.Group("/api/v1")
	protected.Use(middleware.Auth(jwtConfig, middleware.AuthDeps{
		Users:      fakeStatusAdapter{store: store},
		Revocation: service,
	}))
	protected.GET("/user/profile", handler.GetProfile)
	protected.PUT("/user/profile", handler.UpdateProfile)

	return router, service
}

func seedUser(t *testing.T, store *fakeUserStore, email, password, status string) *models.User {
	t.Helper()

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("хеширование пароля: %v", err)
	}

	user := &models.User{
		ID:        testUserID,
		Email:     email,
		Password:  string(hash),
		FullName:  "Test User",
		Status:    status,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := store.CreateUser(context.Background(), user); err != nil {
		t.Fatalf("создание пользователя: %v", err)
	}
	return user
}

func bearer(t *testing.T, service *auth.Service, user *models.User) string {
	t.Helper()

	token, _, err := service.IssueAccessToken(user.ID, user.Email)
	if err != nil {
		t.Fatalf("выпуск токена: %v", err)
	}
	return token
}

func TestRegisterCreatesUserWithHashedPassword(t *testing.T) {
	store := newFakeUserStore()
	router, _ := newAuthTestRouter(t, store)

	body := map[string]string{
		"email":     "new@example.com",
		"password":  "super-secret-password",
		"full_name": "New User",
	}
	recorder := call(t, router, http.MethodPost, "/api/v1/auth/register", "", body)

	if recorder.Code != http.StatusCreated {
		t.Fatalf("ожидался 201, получен %d (%s)", recorder.Code, recorder.Body.String())
	}

	var created struct {
		ID       string `json:"id"`
		Email    string `json:"email"`
		FullName string `json:"full_name"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if created.ID == "" || created.Email != "new@example.com" {
		t.Fatalf("некорректный ответ: %s", recorder.Body.String())
	}

	stored, err := store.GetUser(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("пользователь не сохранён: %v", err)
	}
	if stored.Password == "super-secret-password" {
		t.Fatal("пароль сохранён открытым текстом")
	}
	if !strings.HasPrefix(stored.Password, "$2") {
		t.Fatalf("пароль не похож на bcrypt-хеш: %q", stored.Password)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(stored.Password), []byte("super-secret-password")); err != nil {
		t.Fatalf("хеш не соответствует паролю: %v", err)
	}
}

func TestRegisterRejectsDuplicateEmail(t *testing.T) {
	store := newFakeUserStore()
	seedUser(t, store, "taken@example.com", "password-123", "active")
	router, _ := newAuthTestRouter(t, store)

	body := map[string]string{
		"email":     "taken@example.com",
		"password":  "another-password",
		"full_name": "Duplicate",
	}
	recorder := call(t, router, http.MethodPost, "/api/v1/auth/register", "", body)

	if recorder.Code != http.StatusConflict {
		t.Fatalf("ожидался 409, получен %d (%s)", recorder.Code, recorder.Body.String())
	}
}

func TestRegisterRejectsShortPassword(t *testing.T) {
	router, _ := newAuthTestRouter(t, newFakeUserStore())

	body := map[string]string{
		"email":     "short@example.com",
		"password":  "short",
		"full_name": "Too Short",
	}
	recorder := call(t, router, http.MethodPost, "/api/v1/auth/register", "", body)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("ожидался 400, получен %d (%s)", recorder.Code, recorder.Body.String())
	}
}

func TestLoginReturnsTokenPair(t *testing.T) {
	store := newFakeUserStore()
	seedUser(t, store, "user@example.com", "correct-password", "active")
	router, _ := newAuthTestRouter(t, store)

	body := map[string]string{"email": "user@example.com", "password": "correct-password"}
	recorder := call(t, router, http.MethodPost, "/api/v1/auth/login", "", body)

	if recorder.Code != http.StatusOK {
		t.Fatalf("ожидался 200, получен %d (%s)", recorder.Code, recorder.Body.String())
	}

	var response AuthResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if response.AccessToken == "" || response.RefreshToken == "" {
		t.Fatalf("не выдана пара токенов: %s", recorder.Body.String())
	}
	if response.TokenType != "Bearer" || response.ExpiresIn <= 0 {
		t.Fatalf("некорректные метаданные: %+v", response)
	}
	if response.User.Email != "user@example.com" {
		t.Fatalf("в ответе не тот пользователь: %+v", response.User)
	}
}

func TestLoginRejectsWrongPassword(t *testing.T) {
	store := newFakeUserStore()
	seedUser(t, store, "user@example.com", "correct-password", "active")
	router, _ := newAuthTestRouter(t, store)

	body := map[string]string{"email": "user@example.com", "password": "wrong-password"}
	recorder := call(t, router, http.MethodPost, "/api/v1/auth/login", "", body)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("ожидался 401, получен %d (%s)", recorder.Code, recorder.Body.String())
	}
}

// Заблокированный пользователь не должен получить токены.
func TestLoginRejectsBlockedUser(t *testing.T) {
	store := newFakeUserStore()
	seedUser(t, store, "blocked@example.com", "correct-password", "blocked")
	router, _ := newAuthTestRouter(t, store)

	body := map[string]string{"email": "blocked@example.com", "password": "correct-password"}
	recorder := call(t, router, http.MethodPost, "/api/v1/auth/login", "", body)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("ожидался 403, получен %d (%s)", recorder.Code, recorder.Body.String())
	}
}

func TestGetProfileReturnsCurrentUser(t *testing.T) {
	store := newFakeUserStore()
	user := seedUser(t, store, "user@example.com", "password-123", "active")
	router, service := newAuthTestRouter(t, store)

	recorder := call(t, router, http.MethodGet, "/api/v1/user/profile", bearer(t, service, user), nil)

	if recorder.Code != http.StatusOK {
		t.Fatalf("ожидался 200, получен %d (%s)", recorder.Code, recorder.Body.String())
	}

	var profile UserDTO
	if err := json.Unmarshal(recorder.Body.Bytes(), &profile); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if profile.Email != "user@example.com" || profile.FullName != "Test User" {
		t.Fatalf("некорректный профиль: %+v", profile)
	}
}

func TestUpdateProfileChangesFullName(t *testing.T) {
	store := newFakeUserStore()
	user := seedUser(t, store, "user@example.com", "password-123", "active")
	router, service := newAuthTestRouter(t, store)

	body := map[string]string{"full_name": "Updated Name"}
	recorder := call(t, router, http.MethodPut, "/api/v1/user/profile", bearer(t, service, user), body)

	if recorder.Code != http.StatusOK {
		t.Fatalf("ожидался 200, получен %d (%s)", recorder.Code, recorder.Body.String())
	}

	var profile UserDTO
	if err := json.Unmarshal(recorder.Body.Bytes(), &profile); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if profile.FullName != "Updated Name" {
		t.Fatalf("в ответе старое имя: %+v", profile)
	}

	stored, err := store.GetUser(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("чтение пользователя: %v", err)
	}
	if stored.FullName != "Updated Name" {
		t.Fatalf("имя не сохранено: %q", stored.FullName)
	}
}

func TestUpdateProfileRejectsEmptyFullName(t *testing.T) {
	store := newFakeUserStore()
	user := seedUser(t, store, "user@example.com", "password-123", "active")
	router, service := newAuthTestRouter(t, store)

	body := map[string]string{"full_name": ""}
	recorder := call(t, router, http.MethodPut, "/api/v1/user/profile", bearer(t, service, user), body)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("ожидался 400, получен %d (%s)", recorder.Code, recorder.Body.String())
	}
}

func TestProfileRequiresAuthentication(t *testing.T) {
	router, _ := newAuthTestRouter(t, newFakeUserStore())

	recorder := call(t, router, http.MethodGet, "/api/v1/user/profile", "", nil)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("ожидался 401, получен %d (%s)", recorder.Code, recorder.Body.String())
	}
}
