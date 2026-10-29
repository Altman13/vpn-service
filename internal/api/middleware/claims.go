package middleware

import "vpn-service/internal/services/auth"

// Claims — полезная нагрузка access-токена. Алиас, а не копия структуры:
// поля токена должны описываться в одном месте.
type Claims = auth.Claims
