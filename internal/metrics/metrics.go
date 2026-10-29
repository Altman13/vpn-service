// Package metrics отдаёт метрики в формате Prometheus.
//
// HTTP-метрики снимаются middleware по шаблону маршрута (c.FullPath()), а не по
// реальному пути: иначе /devices/<uuid> создавал бы новую серию на каждый id
// и раздувал кардинальность.
package metrics

import (
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	httpRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "vpn_http_requests_total",
		Help: "Количество HTTP-запросов по методу, маршруту и коду ответа.",
	}, []string{"method", "route", "status"})

	httpDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "vpn_http_request_duration_seconds",
		Help:    "Длительность обработки HTTP-запроса в секундах.",
		Buckets: prometheus.DefBuckets,
	}, []string{"method", "route"})

	devicesCreated = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "vpn_devices_created_total",
		Help: "Созданные VPN-устройства по протоколу и результату.",
	}, []string{"protocol", "result"})

	loginAttempts = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "vpn_auth_login_total",
		Help: "Попытки входа по результату.",
	}, []string{"result"})

	refreshReuse = promauto.NewCounter(prometheus.CounterOpts{
		Name: "vpn_auth_refresh_reuse_total",
		Help: "Повторные предъявления погашенного refresh-токена (признак кражи).",
	})
)

// Middleware собирает метрики по каждому запросу.
func Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		c.Next()

		route := c.FullPath()
		if route == "" {
			// Запрос не совпал ни с одним маршрутом: не подставляем сырой путь,
			// иначе сканеры породят неограниченное число серий.
			route = "unmatched"
		}

		httpRequests.WithLabelValues(c.Request.Method, route, strconv.Itoa(c.Writer.Status())).Inc()
		httpDuration.WithLabelValues(c.Request.Method, route).Observe(time.Since(start).Seconds())
	}
}

// Handler отдаёт снимок метрик в текстовом формате Prometheus.
func Handler() gin.HandlerFunc {
	return gin.WrapH(promhttp.Handler())
}

// DeviceCreated учитывает результат создания устройства.
func DeviceCreated(protocol, result string) {
	devicesCreated.WithLabelValues(protocol, result).Inc()
}

// LoginAttempt учитывает попытку входа: success, invalid_credentials,
// blocked, error.
func LoginAttempt(result string) {
	loginAttempts.WithLabelValues(result).Inc()
}

// RefreshTokenReuse учитывает обнаруженную кражу refresh-токена.
func RefreshTokenReuse() {
	refreshReuse.Inc()
}
