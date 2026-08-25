package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"vpn-service/internal/config"
	"vpn-service/internal/storage/postgres"
	"vpn-service/pkg/logger"
)

type AuthHandler struct {
	jwtConfig config.JWTConfig
	db        *postgres.DB
	log       *logger.Logger
}

func NewAuthHandler(jwtConfig config.JWTConfig, db *postgres.DB, log *logger.Logger) *AuthHandler {
	return &AuthHandler{
		jwtConfig: jwtConfig,
		db:        db,
		log:       log,
	}
}

func (h *AuthHandler) Login(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Login endpoint"})
}

func (h *AuthHandler) Register(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Register endpoint"})
}

func (h *AuthHandler) RefreshToken(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Refresh token endpoint"})
}

func (h *AuthHandler) GetProfile(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"user_id": userID,
		"message": "Get profile endpoint",
	})
}

func (h *AuthHandler) UpdateProfile(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Update profile endpoint"})
}
