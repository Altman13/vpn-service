package handlers

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"vpn-service/internal/api/middleware"
	"vpn-service/internal/services/auth"
	"vpn-service/internal/storage/models"
	"vpn-service/internal/storage/postgres"
	"vpn-service/pkg/logger"
)

// UserStore — операции с пользователями, которые нужны хендлерам.
// Интерфейс вместо *postgres.DB позволяет тестировать регистрацию, вход
// и профиль без реальной базы, а SQL остаётся в слое хранения.
type UserStore interface {
	CreateUser(ctx context.Context, user *models.User) error
	GetUser(ctx context.Context, id string) (*models.User, error)
	GetUserByEmail(ctx context.Context, email string) (*models.User, error)
	UpdateUser(ctx context.Context, id, fullName string) error
}

type AuthHandler struct {
	tokens *auth.Service
	db     UserStore
	log    *logger.Logger
}

func NewAuthHandler(tokens *auth.Service, db UserStore, log *logger.Logger) *AuthHandler {
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
	FullName string `json:"full_name" binding:"required,max=255"`
}

type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

type UpdateProfileRequest struct {
	FullName string `json:"full_name" binding:"required,max=255"`
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

func userDTO(user *models.User) UserDTO {
	return UserDTO{
		ID:        user.ID,
		Email:     user.Email,
		FullName:  user.FullName,
		Status:    user.Status,
		CreatedAt: user.CreatedAt.Format(time.RFC3339),
	}
}

// ---------- Handlers ----------

func (h *AuthHandler) Register(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		h.log.Error("register: hash password: " + err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	now := time.Now()
	user := &models.User{
		ID:        uuid.NewString(),
		Email:     req.Email,
		Password:  string(hash),
		FullName:  req.FullName,
		Status:    "active",
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := h.db.CreateUser(c.Request.Context(), user); err != nil {
		if errors.Is(err, postgres.ErrDuplicateEmail) {
			c.JSON(http.StatusConflict, gin.H{"error": "email already registered"})
			return
		}
		h.log.Error("register: create user: " + err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"id":        user.ID,
		"email":     user.Email,
		"full_name": user.FullName,
		"status":    user.Status,
	})
}

func (h *AuthHandler) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := c.Request.Context()

	user, err := h.db.GetUserByEmail(ctx, req.Email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
			return
		}
		h.log.Error("login: query user: " + err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	// Статус проверяется после пароля, чтобы не раскрывать состояние аккаунта
	// тому, кто его пароля не знает.
	if user.Status != "active" {
		h.log.Error("login: account is not active: " + user.ID)
		c.JSON(http.StatusForbidden, gin.H{"error": "account is not active"})
		return
	}

	accessToken, expiresIn, err := h.tokens.IssueAccessToken(user.ID, user.Email)
	if err != nil {
		h.log.Error("login: issue access token: " + err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	refreshToken, err := h.tokens.IssueRefreshToken(ctx, user.ID, user.Email)
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
		User:         userDTO(user),
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
		switch {
		case errors.Is(err, auth.ErrRefreshTokenReused):
			// Признак кражи: клиент так себя не ведёт. Цепочка уже отозвана,
			// клиенту отвечаем так же, как на любой невалидный токен.
			h.log.Error("refresh: refresh token reuse detected, token family revoked")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh token"})
		case errors.Is(err, auth.ErrInvalidRefreshToken):
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh token"})
		default:
			h.log.Error("refresh: " + err.Error())
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		}
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

	user, err := h.db.GetUser(c.Request.Context(), userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
			return
		}
		h.log.Error("get profile: " + err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	c.JSON(http.StatusOK, userDTO(user))
}

// UpdateProfile меняет отображаемое имя. Email и статус через этот эндпоинт
// не меняются: смена адреса требует подтверждения владения.
func (h *AuthHandler) UpdateProfile(c *gin.Context) {
	userID, ok := middleware.UserID(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	var req UpdateProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := c.Request.Context()

	if err := h.db.UpdateUser(ctx, userID, req.FullName); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
			return
		}
		h.log.Error("update profile: " + err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	user, err := h.db.GetUser(ctx, userID)
	if err != nil {
		h.log.Error("update profile: reload user: " + err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	c.JSON(http.StatusOK, userDTO(user))
}
