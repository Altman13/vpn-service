package middleware

import (
	"math"
	"net/http"
	"strconv"

	"vpn-service/pkg/ratelimit"

	"github.com/gin-gonic/gin"
)

// RateLimit ограничивает частоту запросов по ключу «bucket + IP клиента».
//
// Ключ включает адрес клиента, а не токен: до аутентификации токена ещё нет,
// а перебор пароля — это как раз попытки с одного адреса.
// При nil-лимитере ограничение считается выключенным.
func RateLimit(limiter ratelimit.Limiter, bucket string) gin.HandlerFunc {
	if limiter == nil {
		return func(c *gin.Context) { c.Next() }
	}

	return func(c *gin.Context) {
		key := bucket + ":" + c.ClientIP()

		decision, err := limiter.Allow(c.Request.Context(), key)
		if err != nil {
			// Хранилище счётчиков недоступно: лимитер разрешает запрос
			// (fail-open), чтобы падение Redis не блокировало вход.
			_ = c.Error(err)
		}

		c.Header("X-RateLimit-Limit", strconv.Itoa(decision.Limit))
		c.Header("X-RateLimit-Remaining", strconv.Itoa(decision.Remaining))

		if !decision.Allowed {
			retryAfter := int(math.Ceil(decision.RetryAfter.Seconds()))
			if retryAfter < 1 {
				retryAfter = 1
			}
			c.Header("Retry-After", strconv.Itoa(retryAfter))
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error":               "too many requests",
				"retry_after_seconds": retryAfter,
			})
			return
		}

		c.Next()
	}
}
