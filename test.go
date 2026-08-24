package main

import (
	"log"

	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()

	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok", "message": "VPN Service is running!"})
	})

	r.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{"service": "VPN Service", "status": "active"})
	})

	log.Println("🚀 Server starting on http://localhost:8080")
	log.Println("📡 Health check: http://localhost:8080/health")

	if err := r.Run(":8080"); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}

