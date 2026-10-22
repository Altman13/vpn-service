package handlers

import (
	"database/sql"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"vpn-service/internal/api/middleware"
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

// ---------- DTO ----------

type RegisterRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=6"`
	FullName string `json:"full_name" binding:"required"`
}

type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

type UserDTO struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	FullName  string `json:"full_name"`
	Status    string `json:"status"`
	CreatedAt string `json:"created_at"`
}

type AuthResponse struct {
	AccessToken string  `json:"access_token"`
	ExpiresIn   int64   `json:"expires_in"`
	User        UserDTO `json:"user"`
}

// ---------- Handlers ----------

func (h *AuthHandler) Register(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := c.Request.Context()

	// Проверка занятости email
	var exists bool
	err := h.db.QueryRowxContext(ctx,
		"SELECT EXISTS(SELECT 1 FROM users WHERE email=$1)", req.Email).Scan(&exists)
	if err != nil {
		h.log.Error("register: check email: " + err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}
	if exists {
		c.JSON(http.StatusConflict, gin.H{"error": "email already registered"})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		h.log.Error("register: hash password: " + err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	id := uuid.New()
	_, err = h.db.ExecContext(ctx,
		`INSERT INTO users (id, email, password_hash, full_name, status)
		 VALUES ($1, $2, $3, $4, 'active')`,
		id.String(), req.Email, string(hash), req.FullName)
	if err != nil {
		h.log.Error("register: insert user: " + err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"id":        id.String(),
		"email":     req.Email,
		"full_name": req.FullName,
		"status":    "active",
	})
}

func (h *AuthHandler) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := c.Request.Context()

	var row struct {
		ID           uuid.UUID `db:"id"`
		Email        string    `db:"email"`
		PasswordHash string    `db:"password_hash"`
		FullName     string    `db:"full_name"`
		Status       string    `db:"status"`
		CreatedAt    time.Time `db:"created_at"`
	}

	err := h.db.GetContext(ctx, &row,
		`SELECT id, email, password_hash, full_name, status, created_at
		 FROM users WHERE email=$1`, req.Email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
			return
		}
		h.log.Error("login: query user: " + err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(row.PasswordHash), []byte(req.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	expiresIn := time.Duration(h.jwtConfig.ExpireTime) * time.Hour
	claims := middleware.Claims{
		UserID: row.ID.String(),
		Email:  row.Email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiresIn)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(h.jwtConfig.Secret))
	if err != nil {
		h.log.Error("login: sign token: " + err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	c.JSON(http.StatusOK, AuthResponse{
		AccessToken: signed,
		ExpiresIn:   int64(expiresIn.Seconds()),
		User: UserDTO{
			ID:        row.ID.String(),
			Email:     row.Email,
			FullName:  row.FullName,
			Status:    row.Status,
			CreatedAt: row.CreatedAt.Format(time.RFC3339),
		},
	})
}

func (h *AuthHandler) RefreshToken(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"})
}

func (h *AuthHandler) GetProfile(c *gin.Context) {
	userIDVal, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	userIDStr, ok := userIDVal.(string)
	if !ok || userIDStr == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	ctx := c.Request.Context()

	var row struct {
		ID        uuid.UUID `db:"id"`
		Email     string    `db:"email"`
		FullName  string    `db:"full_name"`
		Status    string    `db:"status"`
		CreatedAt time.Time `db:"created_at"`
	}

	err := h.db.GetContext(ctx, &row,
		`SELECT id, email, full_name, status, created_at FROM users WHERE id=$1`, userIDStr)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
			return
		}
		h.log.Error("get profile: " + err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	c.JSON(http.StatusOK, UserDTO{
		ID:        row.ID.String(),
		Email:     row.Email,
		FullName:  row.FullName,
		Status:    row.Status,
		CreatedAt: row.CreatedAt.Format(time.RFC3339),
	})
}

func (h *AuthHandler) UpdateProfile(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"})
}
