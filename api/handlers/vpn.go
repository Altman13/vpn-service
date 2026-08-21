package handlers

import (
	"net/http"

	"vpn-service/internal/services/vpn"

	"github.com/gin-gonic/gin"
)

type VPNHandler struct {
	vpnManager *vpn.Manager
}

func NewVPNHandler(manager *vpn.Manager) *VPNHandler {
	return &VPNHandler{vpnManager: manager}
}

// CreateDevice - создать устройство для VPN
func (h *VPNHandler) CreateDevice(c *gin.Context) {
	var req struct {
		UserID     string `json:"user_id" binding:"required"`
		DeviceName string `json:"device_name" binding:"required"`
		Protocol   string `json:"protocol" binding:"required,oneof=wireguard openvpn"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	device, err := h.vpnManager.CreateDevice(c.Request.Context(), req.UserID, req.DeviceName, req.Protocol)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, device)
}

// GetDeviceConfig - получить конфигурацию устройства
func (h *VPNHandler) GetDeviceConfig(c *gin.Context) {
	deviceID := c.Param("id")

	config, err := h.vpnManager.GetDeviceConfig(c.Request.Context(), deviceID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "device not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"config": config,
	})
}

// RevokeDevice - отозвать доступ устройства
func (h *VPNHandler) RevokeDevice(c *gin.Context) {
	deviceID := c.Param("id")

	if err := h.vpnManager.RevokeDevice(c.Request.Context(), deviceID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "device revoked successfully"})
}

// GetDevices - получить все устройства пользователя
func (h *VPNHandler) GetDevices(c *gin.Context) {
	userID := c.Query("user_id")
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_id is required"})
		return
	}

	devices, err := h.vpnManager.GetDevicesByUser(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, devices)
}
