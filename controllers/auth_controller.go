package controllers

import (
	"authentication-system/config"
	"authentication-system/database"
	"authentication-system/models"
	"authentication-system/utils"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// Register creates a new user (uses SignUpRequest DTO so password is bound correctly)
func Register(c *gin.Context) {
	var req models.SignUpRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	hashedPassword, err := utils.HashPassword(req.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	user := models.User{
		Email:     req.Email,
		Password:  hashedPassword,
		FirstName: req.FirstName,
		LastName:  req.LastName,
	}

	var existing models.User
	if err := database.DB.Where("email = ?", user.Email).First(&existing).Error; err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "User already registered"})
		return
	}

	if err := database.DB.Create(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "User registered successfully", "user": user.ToUserResponse()})
}

// Login authenticates a user and returns a JWT
func Login(c *gin.Context) {
	var req models.LoginRequestStruct
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user models.User
	if err := database.DB.Where("email = ?", req.Email).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Support legacy plaintext-stored passwords: detect bcrypt hash prefix
	stored := user.Password
	isBcrypt := strings.HasPrefix(stored, "$2a$") || strings.HasPrefix(stored, "$2b$") || strings.HasPrefix(stored, "$2y$")
	if !isBcrypt {
		// legacy plaintext compare
		if stored != req.Password {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
			return
		}

		// migrate to bcrypt on successful plaintext match
		if hashed, err := utils.HashPassword(req.Password); err == nil {
			_ = database.DB.Model(&user).Update("password", hashed).Error
			user.Password = hashed
		}
	} else {
		if err := utils.CheckPasswordHash(stored, req.Password); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
			return
		}
	}

	// Use configured expiry if available
	expiry := time.Hour * 24
	if config.AppConfig.JWTExpiry > 0 {
		expiry = time.Duration(config.AppConfig.JWTExpiry) * time.Second
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": user.ID,
		"email":   user.Email,
		"exp":     time.Now().Add(expiry).Unix(),
	})

	tokenString, err := token.SignedString([]byte(config.AppConfig.JWTSecret))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": tokenString, "user": user.ToUserResponse()})
}

// GetUser returns the currently authenticated user's profile
func GetUser(c *gin.Context) {
	uid, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found in context"})
		return
	}

	var id uint
	switch v := uid.(type) {
	case float64:
		id = uint(v)
	case int:
		id = uint(v)
	case int64:
		id = uint(v)
	case uint:
		id = v
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user id type"})
		return
	}

	var user models.User
	if err := database.DB.First(&user, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	c.JSON(http.StatusOK, user.ToUserResponse())
}

// UpdateUser allows partial updates to the user's profile (and optional password change)
func UpdateUser(c *gin.Context) {
	uid, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found in context"})
		return
	}

	var id uint
	switch v := uid.(type) {
	case float64:
		id = uint(v)
	case int:
		id = uint(v)
	case int64:
		id = uint(v)
	case uint:
		id = v
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user id type"})
		return
	}

	// allow partial updates including optional password change
	var payload struct {
		FirstName *string `json:"first_name"`
		LastName  *string `json:"last_name"`
		Email     *string `json:"email"`
		Password  *string `json:"password"`
	}
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	updates := map[string]interface{}{}
	if payload.FirstName != nil {
		updates["first_name"] = *payload.FirstName
	}
	if payload.LastName != nil {
		updates["last_name"] = *payload.LastName
	}
	if payload.Email != nil {
		updates["email"] = *payload.Email
	}
	if payload.Password != nil {
		hashed, err := utils.HashPassword(*payload.Password)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to hash password"})
			return
		}
		updates["password"] = hashed
	}

	if len(updates) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no fields to update"})
		return
	}

	// perform update
	var user models.User
	if err := database.DB.First(&user, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	if err := database.DB.Model(&user).Updates(updates).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user"})
		return
	}

	// reload
	if err := database.DB.First(&user, id).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load updated user"})
		return
	}

	c.JSON(http.StatusOK, user.ToUserResponse())
}

// ResetPassword handles the actual password reset
func ResetPassword(c *gin.Context) {
	var req models.ResetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var resetToken models.ResetToken
	if err := database.DB.Where("token = ?", req.Token).First(&resetToken).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid reset token"})
		return
	}

	if time.Now().After(resetToken.ExpiresAt) {
		database.DB.Delete(&resetToken)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Reset token has expired"})
		return
	}

	hashedPassword, err := utils.HashPassword(req.NewPassword)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash new password"})
		return
	}

	if err := database.DB.Model(&models.User{}).Where("email = ?", resetToken.Email).Update("password", hashedPassword).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update password"})
		return
	}

	database.DB.Delete(&resetToken)

	c.JSON(http.StatusOK, gin.H{"message": "Password reset successfully"})
}

// DeleteUser deletes the authenticated user's account
func DeleteUser(c *gin.Context) {
	uid, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found in context"})
		return
	}

	var id uint
	switch v := uid.(type) {
	case float64:
		id = uint(v)
	case int:
		id = uint(v)
	case int64:
		id = uint(v)
	case uint:
		id = v
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user id type"})
		return
	}

	result := database.DB.Delete(&models.User{}, id)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete user"})
		return
	}
	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User deleted successfully"})
}