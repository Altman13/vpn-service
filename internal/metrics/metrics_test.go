package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func newRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(Middleware())
	router.GET("/ping", func(c *gin.Context) { c.Status(http.StatusOK) })
	router.GET("/metrics", Handler())
	return router
}

func TestMetricsEndpointExposesHTTPMetrics(t *testing.T) {
	router := newRouter()

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/ping", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("подготовительный запрос: получен %d", recorder.Code)
	}

	scrape := httptest.NewRecorder()
	router.ServeHTTP(scrape, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	if scrape.Code != http.StatusOK {
		t.Fatalf("ожидался 200 от /metrics, получен %d", scrape.Code)
	}

	body := scrape.Body.String()
	for _, want := range []string{
		"vpn_http_requests_total",
		"vpn_http_request_duration_seconds",
		`route="/ping"`,
		`status="200"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("в выдаче нет %q:\n%s", want, body[:min(len(body), 800)])
		}
	}
}

// Метрики не должны расти по числу уникальных путей.
func TestUnmatchedRouteUsesSingleLabel(t *testing.T) {
	router := newRouter()

	for _, path := range []string{"/no-such-path", "/another-missing", "/third"} {
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
	}

	scrape := httptest.NewRecorder()
	router.ServeHTTP(scrape, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	body := scrape.Body.String()
	if !strings.Contains(body, `route="unmatched"`) {
		t.Fatal("несовпавшие маршруты не помечены как unmatched")
	}
	if strings.Contains(body, `route="/no-such-path"`) {
		t.Fatal("в метку попал реальный путь вместо шаблона")
	}
}

func TestDomainCountersAreRegistered(t *testing.T) {
	DeviceCreated("wireguard", "success")
	LoginAttempt("success")
	RefreshTokenReuse()

	router := newRouter()
	scrape := httptest.NewRecorder()
	router.ServeHTTP(scrape, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	body := scrape.Body.String()
	for _, want := range []string{
		"vpn_devices_created_total",
		"vpn_auth_login_total",
		"vpn_auth_refresh_reuse_total",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("в выдаче нет %q", want)
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
