package main

import (
	"authentication-system/config"
	"authentication-system/database"
	"authentication-system/routes"
	"fmt"
	"log"

	"github.com/gin-gonic/gin"
)

func main() {
	// Initialize database connection
	database.Connect()
	database.Migrate()

	// Initialize the router
	router := gin.Default()

	// Setup routes
	routes.SetupRoutes(router)

	// Add a health check endpoint
	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status": "healthy",
			"database": "connected",
		})
	})

	// Start the server
	port := fmt.Sprintf(":%s", config.AppConfig.Port)
	log.Printf("Server starting on port %s", config.AppConfig.Port)
	if err := router.Run(port); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}