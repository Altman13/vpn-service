package redis

import (
	"context"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	refreshTokenPrefix = "auth:refresh:"
	revokedTokenPrefix = "auth:revoked:"
)

// incrementScript увеличивает счётчик и выставляет TTL только при создании
// ключа. Отдельные INCR и EXPIRE оставляли бы окно, в котором ключ живёт
// вечно, если процесс упадёт между командами.
var incrementScript = redis.NewScript(`
local current = redis.call('INCR', KEYS[1])
if current == 1 then
	redis.call('PEXPIRE', KEYS[1], ARGV[1])
end
return current
`)

// Increment реализует ratelimit.Counter.
func (c *Client) Increment(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	if ttl <= 0 {
		ttl = time.Minute
	}
	return incrementScript.Run(ctx, c.Client, []string{key}, ttl.Milliseconds()).Int64()
}

// SaveRefreshToken хранит refresh-токен по его хешу: сам токен в Redis
// не попадает, поэтому утечка дампа не даёт готовых токенов.
func (c *Client) SaveRefreshToken(ctx context.Context, hash, value string, ttl time.Duration) error {
	return c.Client.Set(ctx, refreshTokenPrefix+hash, value, ttl).Err()
}

// LoadRefreshToken возвращает пустую строку, если токена нет.
func (c *Client) LoadRefreshToken(ctx context.Context, hash string) (string, error) {
	value, err := c.Client.Get(ctx, refreshTokenPrefix+hash).Result()
	if errors.Is(err, redis.Nil) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return value, nil
}

func (c *Client) DeleteRefreshToken(ctx context.Context, hash string) error {
	return c.Client.Del(ctx, refreshTokenPrefix+hash).Err()
}

// RevokeAccessToken добавляет jti в блэклист на остаток срока жизни токена:
// держать запись дольше бессмысленно, после истечения токен невалиден сам.
func (c *Client) RevokeAccessToken(ctx context.Context, jti string, ttl time.Duration) error {
	if ttl <= 0 {
		return nil
	}
	return c.Client.Set(ctx, revokedTokenPrefix+jti, "1", ttl).Err()
}

func (c *Client) IsAccessTokenRevoked(ctx context.Context, jti string) (bool, error) {
	if jti == "" {
		return false, nil
	}
	count, err := c.Client.Exists(ctx, revokedTokenPrefix+jti).Result()
	if err != nil {
		return false, err
	}
	return count > 0, nil
}
