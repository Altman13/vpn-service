package routes

import (
	"context"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"

	"vpn-service/internal/api/handlers"
	"vpn-service/internal/api/middleware"
	"vpn-service/internal/config"
	"vpn-service/internal/services/auth"
	"vpn-service/internal/services/vpn"
	"vpn-service/internal/storage/postgres"
	"vpn-service/internal/storage/redis"
	"vpn-service/pkg/logger"
	"vpn-service/pkg/ratelimit"
)

// Адаптеры под handlers.Pinger: у Postgres и Redis разные сигнатуры Ping.

type dbPinger struct {
	db *postgres.DB
}

func (p dbPinger) Ping(ctx context.Context) error {
	return p.db.PingContext(ctx)
}

type cachePinger struct {
	client *redis.Client
}

func (p cachePinger) Ping(ctx context.Context) error {
	return p.client.Ping(ctx).Err()
}

func Setup(cfg *config.Config, db *postgres.DB, cache *redis.Client, log *logger.Logger) *gin.Engine {
	router := gin.New()

	// Middleware
	router.Use(gin.Recovery())
	router.Use(middleware.Logger(log))
	router.Use(corsMiddleware(cfg.Security.CORS.AllowedOrigins))

	// Токены и сессии живут в Redis: это позволяет отзывать доступ
	// и не хранить refresh-токены в открытом виде.
	tokenService := auth.New(cfg.JWT, cache)

	// Инициализация сервисов
	vpnManager := vpn.NewManager(db,
		vpn.WireGuardConfig{
			InterfaceName: cfg.VPN.WireGuard.InterfaceName,
			Port:          cfg.VPN.WireGuard.Port,
			PrivateKey:    cfg.VPN.WireGuard.PrivateKey,
			PublicKey:     cfg.VPN.WireGuard.PublicKey,
			NetworkCIDR:   cfg.VPN.WireGuard.NetworkCIDR,
			Endpoint:      cfg.VPN.WireGuard.Endpoint,
			DNS:           cfg.VPN.WireGuard.DNS,
			AllowedIPs:    cfg.VPN.WireGuard.AllowedIPs,
			Enabled:       cfg.VPN.WireGuard.Enabled,
		},
		vpn.OpenVPNConfig{
			ConfigPath:  cfg.VPN.OpenVPN.ConfigPath,
			Port:        cfg.VPN.OpenVPN.Port,
			NetworkCIDR: cfg.VPN.OpenVPN.NetworkCIDR,
			Enabled:     cfg.VPN.OpenVPN.Enabled,
			PKIDir:      cfg.VPN.OpenVPN.PKIDir,
			Endpoint:    cfg.VPN.OpenVPN.Endpoint,
			Proto:       cfg.VPN.OpenVPN.Proto,
		},
	)

	if cfg.Security.Box != nil {
		vpnManager.UseSecretBox(cfg.Security.Box)
	}

	// Инициализация хендлеров
	vpnHandler := handlers.NewVPNHandler(log, vpnManager)
	authHandler := handlers.NewAuthHandler(tokenService, db, log)
	healthHandler := handlers.NewHealthHandler(dbPinger{db: db}, cachePinger{client: cache})

	limiter := buildRateLimiter(cfg, cache)

	// Публичные маршруты
	api := router.Group("/api/v1")
	{
		// Авторизация: ограничение частоты включается конфигом.
		authGroup := api.Group("/auth")
		{
			authGroup.POST("/login", middleware.RateLimit(limiter, "login"), authHandler.Login)
			authGroup.POST("/register", middleware.RateLimit(limiter, "register"), authHandler.Register)
			authGroup.POST("/refresh", middleware.RateLimit(limiter, "refresh"), authHandler.RefreshToken)
		}

		// Защищенные маршруты
		protected := api.Group("/")
		protected.Use(middleware.Auth(cfg.JWT, middleware.AuthDeps{
			Users:      db,
			Revocation: tokenService,
		}))
		{
			// Выход: отзывает текущий access-токен и refresh-токен.
			protected.POST("/auth/logout", authHandler.Logout)

			// VPN
			vpnGroup := protected.Group("/vpn")
			{
				vpnGroup.POST("/devices", vpnHandler.CreateDevice)
				vpnGroup.GET("/devices", vpnHandler.GetDevices)
				vpnGroup.GET("/devices/:id/config", vpnHandler.GetDeviceConfig)
				vpnGroup.DELETE("/devices/:id", vpnHandler.RevokeDevice)
			}

			// Пользователь
			user := protected.Group("/user")
			{
				user.GET("/profile", authHandler.GetProfile)
				user.PUT("/profile", authHandler.UpdateProfile)
			}
		}
	}

	// Liveness: только факт работы процесса.
	router.GET("/health", healthHandler.Liveness)
	// Readiness: проверяет БД и Redis.
	router.GET("/readyz", healthHandler.Readiness)

	return router
}

// buildRateLimiter собирает лимитер: в Redis — общий для всех реплик,
// иначе — в памяти процесса. nil означает, что ограничение выключено.
func buildRateLimiter(cfg *config.Config, cache *redis.Client) ratelimit.Limiter {
	if !cfg.Security.RateLimit.Enabled {
		return nil
	}

	requests := cfg.Security.RateLimit.Requests
	windowSeconds := cfg.Security.RateLimit.WindowSeconds
	if requests <= 0 {
		requests = 10
	}
	if windowSeconds <= 0 {
		windowSeconds = 60
	}
	window := time.Duration(windowSeconds) * time.Second

	if cache != nil {
		return ratelimit.NewCounterLimiter(cache, requests, window)
	}
	return ratelimit.NewMemoryLimiter(requests, window)
}

// corsMiddleware: пустой список origin означает «CORS выключен» —
// заголовки не отдаются, кросс-доменные запросы браузер блокирует.
func corsMiddleware(allowedOrigins []string) gin.HandlerFunc {
	if len(allowedOrigins) == 0 {
		return func(c *gin.Context) { c.Next() }
	}

	return cors.New(cors.Config{
		AllowOrigins:     allowedOrigins,
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Authorization", "Content-Type"},
		AllowCredentials: false,
		MaxAge:           12 * time.Hour,
	})
}
