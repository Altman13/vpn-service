
package routes

import (
    "github.com/gin-contrib/cors"
    "github.com/gin-gonic/gin"
    "vpn-service/internal/api/handlers"
    "vpn-service/internal/api/middleware"
    "vpn-service/internal/config"
    "vpn-service/internal/services/vpn"
    "vpn-service/internal/storage/postgres"
    "vpn-service/internal/storage/redis"
    "vpn-service/pkg/logger"
)

func Setup(cfg *config.Config, db *postgres.DB, cache *redis.Client, log *logger.Logger) *gin.Engine {
    router := gin.New()

    // Middleware
    router.Use(gin.Recovery())
    router.Use(middleware.Logger(log))
    router.Use(cors.Default())

    // Инициализация сервисов
    vpnManager := vpn.NewManager(db,
        vpn.WireGuardConfig{
            InterfaceName: cfg.VPN.WireGuard.InterfaceName,
            Port:          cfg.VPN.WireGuard.Port,
            PrivateKey:    cfg.VPN.WireGuard.PrivateKey,
            PublicKey:     cfg.VPN.WireGuard.PublicKey,
            NetworkCIDR:   cfg.VPN.WireGuard.NetworkCIDR,
        },
        vpn.OpenVPNConfig{
            ConfigPath:  cfg.VPN.OpenVPN.ConfigPath,
            Port:        cfg.VPN.OpenVPN.Port,
            NetworkCIDR: cfg.VPN.OpenVPN.NetworkCIDR,
        },
    )

    // Инициализация хендлеров
    vpnHandler := handlers.NewVPNHandler(vpnManager)
    authHandler := handlers.NewAuthHandler(cfg.JWT, db, log)

    // Публичные маршруты
    api := router.Group("/api/v1")
    {
        // Авторизация
        auth := api.Group("/auth")
        {
            auth.POST("/login", authHandler.Login)
            auth.POST("/register", authHandler.Register)
            auth.POST("/refresh", authHandler.RefreshToken)
        }

        // Защищенные маршруты
        protected := api.Group("/")
        protected.Use(middleware.Auth(cfg.JWT))
        {
            // VPN
            vpn := protected.Group("/vpn")
            {
                vpn.POST("/devices", vpnHandler.CreateDevice)
                vpn.GET("/devices", vpnHandler.GetDevices)
                vpn.GET("/devices/:id/config", vpnHandler.GetDeviceConfig)
                vpn.DELETE("/devices/:id", vpnHandler.RevokeDevice)
            }

            // Пользователь
            user := protected.Group("/user")
            {
                user.GET("/profile", authHandler.GetProfile)
                user.PUT("/profile", authHandler.UpdateProfile)
            }
        }
    }

    // Health check
    router.GET("/health", func(c *gin.Context) {
        c.JSON(200, gin.H{"status": "ok", "service": "vpn-service"})
    })

    return router
}