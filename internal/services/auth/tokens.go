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

var (
	ErrInvalidRefreshToken = errors.New("invalid refresh token")
	// ErrRefreshTokenReused — предъявлен уже погашенный токен. Это признак
	// кражи: клиент так не делает, значит токен был у кого-то ещё.
	ErrRefreshTokenReused = errors.New("refresh token reuse detected")
)

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
	// Family — цепочка токенов одного входа. При повторном использовании
	// гасится вся цепочка, а не только предъявленный токен.
	Family string `json:"family"`
}

// Store — хранилище refresh-токенов и блэклиста access-токенов.
type Store interface {
	SaveRefreshToken(ctx context.Context, hash, value string, ttl time.Duration) error
	// LoadRefreshToken возвращает пустую строку, если токена нет.
	LoadRefreshToken(ctx context.Context, hash string) (string, error)
	DeleteRefreshToken(ctx context.Context, hash string) error
	RevokeAccessToken(ctx context.Context, jti string, ttl time.Duration) error
	IsAccessTokenRevoked(ctx context.Context, jti string) (bool, error)

	// SaveFamilyToken запоминает текущий (единственный активный) токен семейства.
	SaveFamilyToken(ctx context.Context, family, hash string, ttl time.Duration) error
	// LoadFamilyToken возвращает пустую строку, если семейства нет.
	LoadFamilyToken(ctx context.Context, family string) (string, error)
	DeleteFamilyToken(ctx context.Context, family string) error
	// MarkRefreshUsed оставляет метку о погашенном токене: по ней повторное
	// предъявление отличается от неизвестного токена.
	MarkRefreshUsed(ctx context.Context, hash, family string, ttl time.Duration) error
	// UsedRefreshFamily возвращает семейство погашенного токена или "".
	UsedRefreshFamily(ctx context.Context, hash string) (string, error)
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
	return s.issueRefreshToken(ctx, userID, email, uuid.NewString())
}

func (s *Service) issueRefreshToken(ctx context.Context, userID, email, family string) (string, error) {
	raw := make([]byte, refreshTokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate refresh token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	hash := hashToken(token)
	ttl := s.RefreshTTL()

	record, err := json.Marshal(refreshRecord{UserID: userID, Email: email, Family: family})
	if err != nil {
		return "", fmt.Errorf("encode refresh record: %w", err)
	}

	if err := s.store.SaveRefreshToken(ctx, hash, string(record), ttl); err != nil {
		return "", fmt.Errorf("save refresh token: %w", err)
	}
	if err := s.store.SaveFamilyToken(ctx, family, hash, ttl); err != nil {
		return "", fmt.Errorf("save token family: %w", err)
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
		return "", "", 0, s.handleMissingToken(ctx, hash)
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
	// Метка нужна, чтобы отличить повторное предъявление от неизвестного токена.
	if err := s.store.MarkRefreshUsed(ctx, hash, record.Family, s.RefreshTTL()); err != nil {
		return "", "", 0, fmt.Errorf("mark refresh token used: %w", err)
	}

	accessToken, accessTTL, err = s.IssueAccessToken(record.UserID, record.Email)
	if err != nil {
		return "", "", 0, err
	}
	newRefreshToken, err = s.issueRefreshToken(ctx, record.UserID, record.Email, record.Family)
	if err != nil {
		return "", "", 0, err
	}

	return accessToken, newRefreshToken, accessTTL, nil
}

// handleMissingToken разбирает случай, когда токена нет среди активных.
// Если осталась метка об использовании — токен украли и предъявили повторно,
// поэтому гасится вся цепочка: легитимный клиент получит 401 и войдёт заново.
func (s *Service) handleMissingToken(ctx context.Context, hash string) error {
	family, err := s.store.UsedRefreshFamily(ctx, hash)
	if err != nil {
		return fmt.Errorf("check refresh token reuse: %w", err)
	}
	if family == "" {
		return ErrInvalidRefreshToken
	}
	if err := s.revokeFamily(ctx, family); err != nil {
		return fmt.Errorf("revoke token family: %w", err)
	}
	return ErrRefreshTokenReused
}

func (s *Service) revokeFamily(ctx context.Context, family string) error {
	current, err := s.store.LoadFamilyToken(ctx, family)
	if err != nil {
		return err
	}
	if current != "" {
		if err := s.store.DeleteRefreshToken(ctx, current); err != nil {
			return err
		}
	}
	return s.store.DeleteFamilyToken(ctx, family)
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

	hash := hashToken(refreshToken)
	// Семейство удаляется вместе с токеном: logout не должен оставлять
	// активную ссылку, по которой можно отозвать чужую цепочку.
	if value, err := s.store.LoadRefreshToken(ctx, hash); err == nil && value != "" {
		var record refreshRecord
		if json.Unmarshal([]byte(value), &record) == nil && record.Family != "" {
			if err := s.store.DeleteFamilyToken(ctx, record.Family); err != nil {
				return err
			}
		}
	}

	return s.store.DeleteRefreshToken(ctx, hash)
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
