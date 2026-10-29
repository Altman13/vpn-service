package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

type fakePinger struct {
	err error
}

func (p fakePinger) Ping(context.Context) error {
	return p.err
}

func newHealthRouter(db, cache Pinger) *gin.Engine {
	gin.SetMode(gin.TestMode)

	handler := NewHealthHandler(db, cache)
	router := gin.New()
	router.GET("/health", handler.Liveness)
	router.GET("/readyz", handler.Readiness)
	return router
}

func get(t *testing.T, router *gin.Engine, path string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
	return recorder
}

// Liveness не должен зависеть от БД: иначе упавшая база перезапустит живой под.
func TestLivenessIgnoresDependencies(t *testing.T) {
	failure := errors.New("connection refused")
	router := newHealthRouter(fakePinger{err: failure}, fakePinger{err: failure})

	recorder := get(t, router, "/health")

	if recorder.Code != http.StatusOK {
		t.Fatalf("ожидался 200, получен %d (%s)", recorder.Code, recorder.Body.String())
	}
}

func TestReadinessReportsHealthyDependencies(t *testing.T) {
	router := newHealthRouter(fakePinger{}, fakePinger{})

	recorder := get(t, router, "/readyz")

	if recorder.Code != http.StatusOK {
		t.Fatalf("ожидался 200, получен %d (%s)", recorder.Code, recorder.Body.String())
	}
	body := recorder.Body.String()
	for _, want := range []string{`"database":"ok"`, `"redis":"ok"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("в ответе нет %s: %s", want, body)
		}
	}
}

func TestReadinessFailsWhenDatabaseIsDown(t *testing.T) {
	router := newHealthRouter(fakePinger{err: errors.New("connection refused")}, fakePinger{})

	recorder := get(t, router, "/readyz")

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("ожидался 503, получен %d (%s)", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"database":"unavailable"`) {
		t.Fatalf("не указана недоступная БД: %s", recorder.Body.String())
	}
}

func TestReadinessFailsWhenRedisIsDown(t *testing.T) {
	router := newHealthRouter(fakePinger{}, fakePinger{err: errors.New("connection refused")})

	recorder := get(t, router, "/readyz")

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("ожидался 503, получен %d (%s)", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"redis":"unavailable"`) {
		t.Fatalf("не указан недоступный Redis: %s", recorder.Body.String())
	}
}
