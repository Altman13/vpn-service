package middleware

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"vpn-service/internal/config"
	"vpn-service/internal/services/auth"
)

const testSecret = "test-secret"

type fakeUserStore struct {
	status string
	err    error
}

func (f fakeUserStore) GetUserStatus(context.Context, string) (string, error) {
	return f.status, f.err
}

type fakeRevocation struct {
	revoked bool
	err     error
}

func (f fakeRevocation) IsAccessTokenRevoked(context.Context, string) (bool, error) {
	return f.revoked, f.err
}

func validClaims() Claims {
	return Claims{
		UserID: "11111111-1111-1111-1111-111111111111",
		Email:  "user@example.com",
		Typ:    auth.TokenTypeAccess,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        "token-jti",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
}

func signToken(t *testing.T, method jwt.SigningMethod, secret string, claims Claims) string {
	t.Helper()
	signed, err := jwt.NewWithClaims(method, claims).SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return signed
}

func newRouter(deps AuthDeps) (*gin.Engine, *string) {
	gin.SetMode(gin.TestMode)

	seenUserID := new(string)
	router := gin.New()
	router.GET("/protected",
		Auth(config.JWTConfig{Secret: testSecret, ExpireTime: 1}, deps),
		func(c *gin.Context) {
			if id, ok := UserID(c); ok {
				*seenUserID = id
			}
			c.Status(http.StatusOK)
		},
	)
	return router, seenUserID
}

func doRequest(router *gin.Engine, authorization string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	return recorder
}

func TestAuthRejectsInvalidTokens(t *testing.T) {
	expired := validClaims()
	expired.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Hour))

	noUserID := validClaims()
	noUserID.UserID = ""

	refreshTyped := validClaims()
	refreshTyped.Typ = "refresh"

	noTyp := validClaims()
	noTyp.Typ = ""

	cases := []struct {
		name          string
		authorization string
	}{
		{"нет заголовка", ""},
		{"другая схема", "Basic dXNlcjpwYXNz"},
		{"без токена", "Bearer"},
		{"мусор вместо токена", "Bearer not-a-jwt"},
		{"токен подписан другим секретом", "Bearer " + signToken(t, jwt.SigningMethodHS256, "other-secret", validClaims())},
		{"неподдерживаемый алгоритм", "Bearer " + signToken(t, jwt.SigningMethodHS512, testSecret, validClaims())},
		{"истёкший токен", "Bearer " + signToken(t, jwt.SigningMethodHS256, testSecret, expired)},
		{"токен без user_id", "Bearer " + signToken(t, jwt.SigningMethodHS256, testSecret, noUserID)},
		// refresh-токен подписан тем же ключом, но не должен давать доступ к API.
		{"токен другого типа", "Bearer " + signToken(t, jwt.SigningMethodHS256, testSecret, refreshTyped)},
		{"токен без типа", "Bearer " + signToken(t, jwt.SigningMethodHS256, testSecret, noTyp)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			router, _ := newRouter(AuthDeps{})
			recorder := doRequest(router, tc.authorization)

			if recorder.Code != http.StatusUnauthorized {
				t.Fatalf("ожидался 401, получен %d (%s)", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestAuthAcceptsValidTokenAndPropagatesUserID(t *testing.T) {
	router, seenUserID := newRouter(AuthDeps{})

	claims := validClaims()
	recorder := doRequest(router, "Bearer "+signToken(t, jwt.SigningMethodHS256, testSecret, claims))

	if recorder.Code != http.StatusOK {
		t.Fatalf("ожидался 200, получен %d (%s)", recorder.Code, recorder.Body.String())
	}
	if *seenUserID != claims.UserID {
		t.Fatalf("user_id в контексте: ожидался %q, получен %q", claims.UserID, *seenUserID)
	}
}

func TestAuthChecksUserStatus(t *testing.T) {
	cases := []struct {
		name       string
		store      UserStatusStore
		wantStatus int
	}{
		{"активный пользователь", fakeUserStore{status: "active"}, http.StatusOK},
		{"заблокированный пользователь", fakeUserStore{status: "blocked"}, http.StatusForbidden},
		{"пользователь удалён", fakeUserStore{err: sql.ErrNoRows}, http.StatusUnauthorized},
		{"хранилище недоступно", fakeUserStore{err: errors.New("connection refused")}, http.StatusServiceUnavailable},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			router, _ := newRouter(AuthDeps{Users: tc.store})
			header := "Bearer " + signToken(t, jwt.SigningMethodHS256, testSecret, validClaims())

			recorder := doRequest(router, header)
			if recorder.Code != tc.wantStatus {
				t.Fatalf("ожидался %d, получен %d (%s)", tc.wantStatus, recorder.Code, recorder.Body.String())
			}
		})
	}
}

// После logout токен должен перестать работать, не дожидаясь истечения exp.
func TestAuthRejectsRevokedToken(t *testing.T) {
	router, _ := newRouter(AuthDeps{Revocation: fakeRevocation{revoked: true}})

	recorder := doRequest(router, "Bearer "+signToken(t, jwt.SigningMethodHS256, testSecret, validClaims()))

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("ожидался 401, получен %d (%s)", recorder.Code, recorder.Body.String())
	}
}

// Если блэклист недоступен, доступ не выдаётся: нельзя проверить отзыв.
func TestAuthFailsClosedWhenRevocationStoreIsDown(t *testing.T) {
	router, _ := newRouter(AuthDeps{Revocation: fakeRevocation{err: errors.New("redis is down")}})

	recorder := doRequest(router, "Bearer "+signToken(t, jwt.SigningMethodHS256, testSecret, validClaims()))

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("ожидался 503, получен %d (%s)", recorder.Code, recorder.Body.String())
	}
}
