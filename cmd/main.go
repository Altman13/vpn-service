package main

import (
    "context"
    "log"
    "net/http"
    "os"
    "os/signal"
    "syscall"
    "time"

    "vpn-service/internal/api/routes"
    "vpn-service/internal/config"
    "vpn-service/internal/logger"
    "vpn-service/internal/storage/postgres"
    "vpn-service/internal/storage/redis"
)

func main() {
    // Загрузка конфигурации
    cfg, err := config.Load()
    if err != nil {
        log.Fatalf("Failed to load config: %v", err)
    }

    // Инициализация логгера
    log := logger.New(cfg.LogLevel)

    // Инициализация базы данных
    db, err := postgres.New(cfg.Database)
    if err != nil {
        log.Fatal("Failed to connect to database", "error", err)
    }
    defer db.Close()

    // Инициализация Redis
    cache, err := redis.New(cfg.Redis)
    if err != nil {
        log.Fatal("Failed to connect to Redis", "error", err)
    }
    defer cache.Close()

    // Создание маршрутов
    router := routes.Setup(cfg, db, cache, log)

    // HTTP сервер
    srv := &http.Server{
        Addr:         cfg.ServerAddress,
        Handler:      router,
        ReadTimeout:  15 * time.Second,
        WriteTimeout: 15 * time.Second,
        IdleTimeout:  60 * time.Second,
    }

    // Запуск в горутине
    go func() {
        log.Info("Starting server", "address", cfg.ServerAddress)
        if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
            log.Fatal("Failed to start server", "error", err)
        }
    }()

    // Graceful shutdown
    quit := make(chan os.Signal, 1)
    signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
    <-quit

    log.Info("Shutting down server...")

    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    if err := srv.Shutdown(ctx); err != nil {
        log.Fatal("Server forced to shutdown", "error", err)
    }

    log.Info("Server exited properly")
}