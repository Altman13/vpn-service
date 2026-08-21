# VPN Service

Готовый к продакшну VPN сервис на Go с поддержкой WireGuard и OpenVPN.

## Особенности

- 🔒 Поддержка WireGuard и OpenVPN
- 🔑 JWT аутентификация
- 📊 Метрики и мониторинг
- 🐳 Docker и Kubernetes готовность
- 🔄 Graceful shutdown
- 📝 Структурированное логирование
- 🗄️ PostgreSQL + Redis

## Быстрый старт

```bash
# Клонирование
git clone https://github.com/yourusername/vpn-service
cd vpn-service

# Установка зависимостей
go mod download

# Настройка конфигурации
cp configs/config.example.yaml configs/config.yaml
# Отредактируйте config.yaml под свои нужды

# Запуск с Docker (PostgreSQL + Redis)
make docker-up

# Запуск приложения
make run