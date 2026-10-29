package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"vpn-service/pkg/ratelimit"

	"github.com/gin-gonic/gin"
)

func newRateLimitedRouter(limiter ratelimit.Limiter) *gin.Engine {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.POST("/login", RateLimit(limiter, "login"), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	return router
}

func attemptLogin(router *gin.Engine, ip string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	req.RemoteAddr = ip + ":12345"
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	return recorder
}

func TestRateLimitRejectsExcessRequests(t *testing.T) {
	router := newRateLimitedRouter(ratelimit.NewMemoryLimiter(2, time.Minute))

	for attempt := 1; attempt <= 2; attempt++ {
		if recorder := attemptLogin(router, "10.0.0.1"); recorder.Code != http.StatusOK {
			t.Fatalf("попытка %d: получен %d", attempt, recorder.Code)
		}
	}

	recorder := attemptLogin(router, "10.0.0.1")
	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("ожидался 429, получен %d", recorder.Code)
	}
	if recorder.Header().Get("Retry-After") == "" {
		t.Fatal("не выставлен заголовок Retry-After")
	}
	if recorder.Header().Get("X-RateLimit-Remaining") != "0" {
		t.Fatalf("X-RateLimit-Remaining=%q, ожидался 0", recorder.Header().Get("X-RateLimit-Remaining"))
	}
}

// Клиенты не должны мешать друг другу: лимит считается по IP.
func TestRateLimitIsPerClient(t *testing.T) {
	router := newRateLimitedRouter(ratelimit.NewMemoryLimiter(1, time.Minute))

	if recorder := attemptLogin(router, "10.0.0.1"); recorder.Code != http.StatusOK {
		t.Fatalf("первый клиент: получен %d", recorder.Code)
	}
	if recorder := attemptLogin(router, "10.0.0.1"); recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("повтор первого клиента: получен %d", recorder.Code)
	}
	if recorder := attemptLogin(router, "10.0.0.2"); recorder.Code != http.StatusOK {
		t.Fatalf("второй клиент заблокирован чужим лимитом: получен %d", recorder.Code)
	}
}

// nil-лимитер означает выключенное ограничение.
func TestRateLimitDisabled(t *testing.T) {
	router := newRateLimitedRouter(nil)

	for attempt := 0; attempt < 20; attempt++ {
		if recorder := attemptLogin(router, "10.0.0.1"); recorder.Code != http.StatusOK {
			t.Fatalf("попытка %d: получен %d", attempt, recorder.Code)
		}
	}
}
