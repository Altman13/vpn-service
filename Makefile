.PHONY: run build test docker-up docker-down migrate-up migrate-down clean

# Запуск приложения
run:
	go run cmd/server/main.go

# Сборка бинарника
build:
	go build -o bin/vpn-service cmd/server/main.go

# Тесты
test:
	go test -v ./...

# Интеграционные тесты: нужна живая PostgreSQL с применёнными миграциями.
# Пример: docker run -d --name vpn-pg -e POSTGRES_PASSWORD=postgres \
#           -e POSTGRES_DB=vpn_service -p 15432:5432 postgres:15-alpine
# TEST_DATABASE_DSN='postgres://postgres:postgres@127.0.0.1:15432/vpn_service?sslmode=disable'
integration-test:
	go test -tags integration -run Integration -v ./...

# Docker
docker-up:
	docker-compose -f deployments/docker/docker-compose.yml up -d

docker-down:
	docker-compose -f deployments/docker/docker-compose.yml down

# Миграции
migrate-up:
	goose -dir scripts/migrations up

migrate-down:
	goose -dir scripts/migrations down

# Линтер
lint:
	golangci-lint run

# Clean
clean:
	rm -rf bin/
	go clean

# Генерация кода
generate:
	go generate ./...