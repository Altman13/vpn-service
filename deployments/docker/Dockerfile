FROM golang:1.26-alpine AS builder

WORKDIR /app

# Установка зависимостей
RUN apk add --no-cache git make

# Копирование go.mod и go.sum
COPY go.mod go.sum ./
RUN go mod download

# Копирование исходного кода
COPY . .

# Сборка приложения
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o vpn-service cmd/server/main.go

# Финальный образ
FROM alpine:latest

RUN apk --no-cache add ca-certificates wireguard-tools

WORKDIR /root/

# Копирование бинарника
COPY --from=builder /app/vpn-service .
# COPY --from=builder /app/configs ./configs

# Открытие портов
EXPOSE 8080 51820/udp

CMD ["./vpn-service"]