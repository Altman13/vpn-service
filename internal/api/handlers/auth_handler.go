package handlers

import (
	"database/sql"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"vpn-service/internal/api/middleware"
	"vpn-service/internal/services/auth"
	"vpn-service/internal/storage/postgres"
	"vpn-service/pkg/logger"
)

type AuthHandler struct {
	tokens *auth.Service
	db     *postgres.DB
	log    *logger.Logger
}

func NewAuthHandler(tokens *auth.Service, db *postgres.DB, log *logger.Logger) *AuthHandler {
	return &AuthHandler{
		tokens: tokens,
		db:     db,
		log:    log,
	}
}

// ---------- DTO ----------

type RegisterRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8,max=72"`
	FullName string `json:"full_name" binding:"required"`
}

type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

// refreshRequest используется и при обмене refresh-токена, и при logout,
// поэтому поле необязательное.
type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type UserDTO struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	FullName  string `json:"full_name"`
	Status    string `json:"status"`
	CreatedAt string `json:"created_at"`
}

type AuthResponse struct {
	AccessToken  string  `json:"access_token"`
	RefreshToken string  `json:"refresh_token,omitempty"`
	TokenType    string  `json:"token_type"`
	ExpiresIn    int64   `json:"expires_in"`
	User         UserDTO `json:"user"`
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

	// Статус проверяется после пароля, чтобы не раскрывать состояние аккаунта
	// тому, кто его пароля не знает.
	if row.Status != "active" {
		h.log.Error("login: account is not active: " + row.ID.String())
		c.JSON(http.StatusForbidden, gin.H{"error": "account is not active"})
		return
	}

	accessToken, expiresIn, err := h.tokens.IssueAccessToken(row.ID.String(), row.Email)
	if err != nil {
		h.log.Error("login: issue access token: " + err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	refreshToken, err := h.tokens.IssueRefreshToken(ctx, row.ID.String(), row.Email)
	if err != nil {
		h.log.Error("login: issue refresh token: " + err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	c.JSON(http.StatusOK, AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(expiresIn.Seconds()),
		User: UserDTO{
			ID:        row.ID.String(),
			Email:     row.Email,
			FullName:  row.FullName,
			Status:    row.Status,
			CreatedAt: row.CreatedAt.Format(time.RFC3339),
		},
	})
}

// RefreshToken обменивает refresh-токен на новую пару. Старый токен
// при этом погашается, поэтому повторная отправка вернёт 401.
func (h *AuthHandler) RefreshToken(c *gin.Context) {
	var req refreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.RefreshToken == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "refresh_token is required"})
		return
	}

	accessToken, refreshToken, expiresIn, err := h.tokens.RotateRefreshToken(c.Request.Context(), req.RefreshToken)
	if err != nil {
		if errors.Is(err, auth.ErrInvalidRefreshToken) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh token"})
			return
		}
		h.log.Error("refresh: " + err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"token_type":    "Bearer",
		"expires_in":    int64(expiresIn.Seconds()),
	})
}

// Logout отзывает текущий access-токен (через блэклист) и, если он передан,
// refresh-токен.
func (h *AuthHandler) Logout(c *gin.Context) {
	claims, ok := middleware.ClaimsFrom(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	ctx := c.Request.Context()

	var req refreshRequest
	// Тело необязательно: достаточно access-токена.
	_ = c.ShouldBindJSON(&req)

	if err := h.tokens.RevokeAccessToken(ctx, claims); err != nil {
		h.log.Error("logout: revoke access token: " + err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}
	if err := h.tokens.RevokeRefreshToken(ctx, req.RefreshToken); err != nil {
		h.log.Error("logout: revoke refresh token: " + err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "logged out"})
}

func (h *AuthHandler) GetProfile(c *gin.Context) {
	userID, ok := middleware.UserID(c)
	if !ok {
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
		`SELECT id, email, full_name, status, created_at FROM users WHERE id=$1`, userID)
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
