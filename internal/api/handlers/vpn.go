package handlers

import (
	"errors"
	"net/http"

	"vpn-service/internal/api/middleware"
	"vpn-service/internal/services/vpn"
	"vpn-service/pkg/logger"

	"github.com/gin-gonic/gin"
)

type VPNHandler struct {
	vpnManager *vpn.Manager
	log        *logger.Logger
}

func NewVPNHandler(log *logger.Logger, manager *vpn.Manager) *VPNHandler {
	return &VPNHandler{
		vpnManager: manager,
		log:        log,
	}
}

// createDeviceRequest намеренно не содержит user_id: владелец устройства
// берётся из JWT, иначе любой пользователь мог бы создавать устройства
// на чужой аккаунт.
type createDeviceRequest struct {
	DeviceName string `json:"device_name" binding:"required,max=255"`
	Protocol   string `json:"protocol" binding:"required,oneof=wireguard openvpn"`
}

// CreateDevice - создать устройство для VPN
func (h *VPNHandler) CreateDevice(c *gin.Context) {
	userID, ok := middleware.UserID(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	var req createDeviceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	device, err := h.vpnManager.CreateDevice(c.Request.Context(), userID, req.DeviceName, req.Protocol)
	if err != nil {
		switch {
		case errors.Is(err, vpn.ErrUnsupportedProtocol):
			c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported protocol"})
		case isNotConfigured(err):
			h.log.Error("create device: " + err.Error())
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "requested vpn provider is not configured"})
		default:
			// Детали ошибки (текст SQL, внутренние пути) остаются в логах.
			h.log.Error("create device: " + err.Error())
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		}
		return
	}

	c.JSON(http.StatusCreated, device)
}

// GetDeviceConfig - получить конфигурацию устройства
func (h *VPNHandler) GetDeviceConfig(c *gin.Context) {
	userID, ok := middleware.UserID(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	config, err := h.vpnManager.GetDeviceConfig(c.Request.Context(), userID, c.Param("id"))
	if err != nil {
		switch {
		case errors.Is(err, vpn.ErrDeviceNotFound):
			c.JSON(http.StatusNotFound, gin.H{"error": "device not found"})
		case isNotConfigured(err):
			h.log.Error("get device config: " + err.Error())
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "requested vpn provider is not configured"})
		default:
			h.log.Error("get device config: " + err.Error())
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"config": config,
	})
}

// RevokeDevice - отозвать доступ устройства
func (h *VPNHandler) RevokeDevice(c *gin.Context) {
	userID, ok := middleware.UserID(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	if err := h.vpnManager.RevokeDevice(c.Request.Context(), userID, c.Param("id")); err != nil {
		switch {
		case errors.Is(err, vpn.ErrDeviceNotFound):
			c.JSON(http.StatusNotFound, gin.H{"error": "device not found"})
		case isNotConfigured(err):
			h.log.Error("revoke device: " + err.Error())
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "requested vpn provider is not configured"})
		default:
			h.log.Error("revoke device: " + err.Error())
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "device revoked successfully"})
}

// GetDevices - получить все устройства текущего пользователя
func (h *VPNHandler) GetDevices(c *gin.Context) {
	userID, ok := middleware.UserID(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	devices, err := h.vpnManager.GetDevicesByUser(c.Request.Context(), userID)
	if err != nil {
		h.log.Error("get devices: " + err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	c.JSON(http.StatusOK, devices)
}

// isNotConfigured сообщает, что протокол запрошен, но не настроен на сервере.
// Это не вина клиента, поэтому не 4xx.
func isNotConfigured(err error) bool {
	return errors.Is(err, vpn.ErrWireGuardNotConfigured) || errors.Is(err, vpn.ErrOpenVPNNotConfigured)
}
