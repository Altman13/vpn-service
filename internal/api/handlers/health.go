package handlers

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// Pinger — минимальный интерфейс зависимости, которую можно проверить.
// Реализации-адаптеры живут рядом с роутером, чтобы хендлер не зависел
// от конкретных клиентов Postgres и Redis.
type Pinger interface {
	Ping(ctx context.Context) error
}

type HealthHandler struct {
	db    Pinger
	cache Pinger
}

func NewHealthHandler(db, cache Pinger) *HealthHandler {
	return &HealthHandler{db: db, cache: cache}
}

// Liveness отвечает только за то, что процесс жив. Зависимости здесь
// проверять нельзя: иначе упавшая БД перезапустит здоровый контейнер.
func (h *HealthHandler) Liveness(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":  "ok",
		"service": "vpn-service",
	})
}

// Readiness проверяет, что сервис может обслуживать запросы: живы БД и Redis.
// На этот эндпоинт должны смотреть readinessProbe и балансировщик.
func (h *HealthHandler) Readiness(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
	defer cancel()

	checks := make(map[string]string, 2)
	ready := true

	if err := h.db.Ping(ctx); err != nil {
		checks["database"] = "unavailable"
		ready = false
	} else {
		checks["database"] = "ok"
	}

	if err := h.cache.Ping(ctx); err != nil {
		checks["redis"] = "unavailable"
		ready = false
	} else {
		checks["redis"] = "ok"
	}

	status := http.StatusOK
	state := "ready"
	if !ready {
		status = http.StatusServiceUnavailable
		state = "not ready"
	}

	c.JSON(status, gin.H{
		"status": state,
		"checks": checks,
	})
}
