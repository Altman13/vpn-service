module vpn-service

go 1.21

require (
    github.com/gin-contrib/cors v1.5.0
    github.com/gin-gonic/gin v1.9.1
    github.com/golang-jwt/jwt/v5 v5.2.0
    github.com/jmoiron/sqlx v1.3.5
    github.com/lib/pq v1.10.9
    github.com/redis/go-redis/v9 v9.3.1
    github.com/spf13/viper v1.18.2
    go.uber.org/zap v1.26.0
    golang.org/x/crypto v0.18.0
    golang.zx2c4.com/wireguard/wgctrl v0.0.0-20230429144221-925a1e7659e6
)