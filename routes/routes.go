package routes

import (
	"authentication-system/controllers"
	"authentication-system/middleware"

	"github.com/gin-gonic/gin"
)

func SetupRoutes(router *gin.Engine) {
	// public routes - no authentication required
	public := router.Group("/api/v1")
	{
		public.POST("/register", controllers.Register)
		public.POST("/login", controllers.Login)
		// public.POST("/reset-password", controllers.InitiatePasswordReset) 
		public.POST("/reset-password/confirm", controllers.ResetPassword)
	}

	// protected routes - require authentication
	protected := router.Group("/api/v1")
	protected.Use(middleware.AuthMiddleware())
	{
		protected.GET("/users", controllers.GetUser)
		protected.PUT("/users", controllers.UpdateUser)
		protected.DELETE("/users", controllers.DeleteUser)
	}
}