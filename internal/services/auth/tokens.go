// Package auth выпускает и отзывает токены доступа.
//
// Access-токен — подписанный JWT с коротким сроком жизни и уникальным jti.
// Refresh-токен — непрозрачная случайная строка: в Redis хранится только её
// SHA-256, поэтому утечка хранилища не даёт готовых токенов. Refresh-токен
// одноразовый: при обмене он удаляется и выпускается новый.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"vpn-service/internal/config"
)

const (
	// TokenTypeAccess отличает access-токен от любого другого JWT,
	// чтобы refresh-токен нельзя было предъявить как Bearer.
	TokenTypeAccess = "access"

	defaultAccessTTL  = time.Hour
	defaultRefreshTTL = 30 * 24 * time.Hour
	refreshTokenBytes = 32
)

var ErrInvalidRefreshToken = errors.New("invalid refresh token")

// Claims — полезная нагрузка access-токена.
type Claims struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	Typ    string `json:"typ,omitempty"`
	jwt.RegisteredClaims
}

type refreshRecord struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
}

// Store — хранилище refresh-токенов и блэклиста access-токенов.
type Store interface {
	SaveRefreshToken(ctx context.Context, hash, value string, ttl time.Duration) error
	// LoadRefreshToken возвращает пустую строку, если токена нет.
	LoadRefreshToken(ctx context.Context, hash string) (string, error)
	DeleteRefreshToken(ctx context.Context, hash string) error
	RevokeAccessToken(ctx context.Context, jti string, ttl time.Duration) error
	IsAccessTokenRevoked(ctx context.Context, jti string) (bool, error)
}

type Service struct {
	cfg   config.JWTConfig
	store Store
	now   func() time.Time
}

func New(cfg config.JWTConfig, store Store) *Service {
	return &Service{cfg: cfg, store: store, now: time.Now}
}

func (s *Service) AccessTTL() time.Duration {
	if s.cfg.ExpireTime <= 0 {
		return defaultAccessTTL
	}
	return time.Duration(s.cfg.ExpireTime) * time.Hour
}

func (s *Service) RefreshTTL() time.Duration {
	if s.cfg.RefreshExpireTime <= 0 {
		return defaultRefreshTTL
	}
	return time.Duration(s.cfg.RefreshExpireTime) * time.Hour
}

func (s *Service) IssueAccessToken(userID, email string) (string, time.Duration, error) {
	ttl := s.AccessTTL()
	now := s.now()

	claims := Claims{
		UserID: userID,
		Email:  email,
		Typ:    TokenTypeAccess,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.NewString(),
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}

	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(s.cfg.Secret))
	if err != nil {
		return "", 0, fmt.Errorf("sign access token: %w", err)
	}
	return signed, ttl, nil
}

func (s *Service) IssueRefreshToken(ctx context.Context, userID, email string) (string, error) {
	raw := make([]byte, refreshTokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate refresh token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)

	record, err := json.Marshal(refreshRecord{UserID: userID, Email: email})
	if err != nil {
		return "", fmt.Errorf("encode refresh record: %w", err)
	}

	if err := s.store.SaveRefreshToken(ctx, hashToken(token), string(record), s.RefreshTTL()); err != nil {
		return "", fmt.Errorf("save refresh token: %w", err)
	}
	return token, nil
}

// RotateRefreshToken обменивает refresh-токен на новую пару.
// Старый токен при этом погашается: повторное использование вернёт ошибку.
func (s *Service) RotateRefreshToken(ctx context.Context, refreshToken string) (accessToken, newRefreshToken string, accessTTL time.Duration, err error) {
	if refreshToken == "" {
		return "", "", 0, ErrInvalidRefreshToken
	}

	hash := hashToken(refreshToken)
	value, err := s.store.LoadRefreshToken(ctx, hash)
	if err != nil {
		return "", "", 0, fmt.Errorf("load refresh token: %w", err)
	}
	if value == "" {
		return "", "", 0, ErrInvalidRefreshToken
	}

	var record refreshRecord
	if err := json.Unmarshal([]byte(value), &record); err != nil || record.UserID == "" {
		return "", "", 0, ErrInvalidRefreshToken
	}

	// Погашение до выпуска новой пары: если выпуск упадёт, токен уже
	// недействителен, и клиент получит понятную ошибку вместо двух живых токенов.
	if err := s.store.DeleteRefreshToken(ctx, hash); err != nil {
		return "", "", 0, fmt.Errorf("consume refresh token: %w", err)
	}

	accessToken, accessTTL, err = s.IssueAccessToken(record.UserID, record.Email)
	if err != nil {
		return "", "", 0, err
	}
	newRefreshToken, err = s.IssueRefreshToken(ctx, record.UserID, record.Email)
	if err != nil {
		return "", "", 0, err
	}

	return accessToken, newRefreshToken, accessTTL, nil
}

// RevokeAccessToken заносит jti в блэклист до истечения срока токена.
func (s *Service) RevokeAccessToken(ctx context.Context, claims *Claims) error {
	if claims == nil || claims.ID == "" {
		return nil
	}

	ttl := s.AccessTTL()
	if claims.ExpiresAt != nil {
		ttl = claims.ExpiresAt.Time.Sub(s.now())
	}
	if ttl <= 0 {
		return nil
	}

	return s.store.RevokeAccessToken(ctx, claims.ID, ttl)
}

func (s *Service) RevokeRefreshToken(ctx context.Context, refreshToken string) error {
	if refreshToken == "" {
		return nil
	}
	return s.store.DeleteRefreshToken(ctx, hashToken(refreshToken))
}

func (s *Service) IsAccessTokenRevoked(ctx context.Context, jti string) (bool, error) {
	if jti == "" {
		return false, nil
	}
	return s.store.IsAccessTokenRevoked(ctx, jti)
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
