package middleware

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strings"

	"vpn-service/internal/config"
	"vpn-service/internal/services/auth"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

const (
	contextUserIDKey    = "user_id"
	contextUserEmailKey = "user_email"
	contextClaimsKey    = "auth_claims"

	// userStatusActive — единственный статус, дающий доступ к API.
	userStatusActive = "active"
)

// UserStatusStore позволяет middleware убедиться, что пользователь из токена
// всё ещё существует и не заблокирован.
type UserStatusStore interface {
	GetUserStatus(ctx context.Context, userID string) (string, error)
}

// RevocationChecker сообщает, отозван ли access-токен (например, после logout).
type RevocationChecker interface {
	IsAccessTokenRevoked(ctx context.Context, jti string) (bool, error)
}

// AuthDeps — зависимости проверки доступа. nil-поле отключает
// соответствующую проверку; в рабочей конфигурации заданы оба.
type AuthDeps struct {
	Users      UserStatusStore
	Revocation RevocationChecker
}

// Auth проверяет Bearer-токен, его тип и актуальное состояние пользователя.
func Auth(cfg config.JWTConfig, deps AuthDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString, ok := bearerToken(c.GetHeader("Authorization"))
		if !ok {
			abortJSON(c, http.StatusUnauthorized, "authorization header required")
			return
		}

		claims := &Claims{}
		token, err := jwt.ParseWithClaims(
			tokenString,
			claims,
			func(*jwt.Token) (interface{}, error) {
				return []byte(cfg.Secret), nil
			},
			// Фиксируем алгоритм: без этого токен, подписанный другим
			// HMAC-вариантом, считался бы валидным.
			jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		)
		if err != nil || !token.Valid || claims.UserID == "" {
			abortJSON(c, http.StatusUnauthorized, "invalid token")
			return
		}
		// Refresh-токен не является ключом доступа, даже если подписан тем же ключом.
		if claims.Typ != auth.TokenTypeAccess {
			abortJSON(c, http.StatusUnauthorized, "invalid token type")
			return
		}

		if deps.Revocation != nil {
			revoked, err := deps.Revocation.IsAccessTokenRevoked(c.Request.Context(), claims.ID)
			switch {
			case err != nil:
				abortJSON(c, http.StatusServiceUnavailable, "authorization temporarily unavailable")
				return
			case revoked:
				abortJSON(c, http.StatusUnauthorized, "token revoked")
				return
			}
		}

		if deps.Users != nil {
			status, err := deps.Users.GetUserStatus(c.Request.Context(), claims.UserID)
			switch {
			case errors.Is(err, sql.ErrNoRows):
				// Пользователь удалён, а токен ещё жив.
				abortJSON(c, http.StatusUnauthorized, "invalid token")
				return
			case err != nil:
				abortJSON(c, http.StatusServiceUnavailable, "authorization temporarily unavailable")
				return
			case status != userStatusActive:
				abortJSON(c, http.StatusForbidden, "account is not active")
				return
			}
		}

		c.Set(contextUserIDKey, claims.UserID)
		c.Set(contextUserEmailKey, claims.Email)
		c.Set(contextClaimsKey, claims)

		c.Next()
	}
}

// UserID возвращает идентификатор аутентифицированного пользователя.
// Единственный доверенный источник user_id в хендлерах.
func UserID(c *gin.Context) (string, bool) {
	value, exists := c.Get(contextUserIDKey)
	if !exists {
		return "", false
	}
	userID, ok := value.(string)
	if !ok || userID == "" {
		return "", false
	}
	return userID, true
}

// UserEmail возвращает email аутентифицированного пользователя.
func UserEmail(c *gin.Context) string {
	if value, exists := c.Get(contextUserEmailKey); exists {
		if email, ok := value.(string); ok {
			return email
		}
	}
	return ""
}

// ClaimsFrom возвращает проверенные claims текущего запроса. Нужен там, где
// важны jti и срок жизни токена (например, при logout).
func ClaimsFrom(c *gin.Context) (*auth.Claims, bool) {
	value, exists := c.Get(contextClaimsKey)
	if !exists {
		return nil, false
	}
	claims, ok := value.(*auth.Claims)
	return claims, ok
}

func bearerToken(header string) (string, bool) {
	parts := strings.Fields(header)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
		return "", false
	}
	return parts[1], true
}

func abortJSON(c *gin.Context, status int, message string) {
	c.Header("WWW-Authenticate", "Bearer")
	c.AbortWithStatusJSON(status, gin.H{"error": message})
}
