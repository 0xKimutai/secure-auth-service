package models

import (
	"fmt"
	"time"
)

type User struct {
	ID					uint    `gorm:"primaryKey" json:"id"`
	Email				string  `gorm:"unique; not null" json:"email"`
	Password			string  `gorm:"not null" json:"-"`
	FirstName			string  `json:"first_name"`
	LastName			string  `json:"last_name"`
	IsEmailVerified		bool	`gorm:"default:false" json:"is_email_verified"`
	ResetToken			string  `json:"-"`
	ResetTokenExpiry	*time.Time `json:"-"`
	CreatedAt			time.Time `json:"created_at"`
	UpdatedAt			time.Time `json:"updated_at"`
	DeletedAt			*time.Time `gorm:"index" json:"-"`
}

// table name -> specifies the table name for user model
func (User) TableName() string {
	return "users"
}

// Request DTOS (Data Transfer Objects)
type SignUpRequest struct {
	Email  		string `json:"email" binding:"required,email"`
	Password 	string	`json:"password" binding:"required,min=8"`
	FirstName 	string	`json:"first_name" binding:"required"`
	LastName 	string	`json:"last_name" binding:"required"`
}

type LoginRequestStruct struct {
	Email      string `json:"email" binding:"required,email"`
	Password   string `json:"password" binding:"required"`
}

type ForgotPasswordRequest struct {
	Email      string `json:"email" binding:"required,email"`

}

type ResetPasswordRequest struct {
	Token      	string `json:"token" binding:"required"`
	NewPassword string `json:"new_password" binding:"required,min=8"`
}

type RefreshTokenRequest struct {
	RefreshToken   string `json:"refresh_token" binding:"required"`
}

//response DTOS
type UserResponse struct {
	ID        		string `json:"id"`
	Email     		string `json:"email"`
	FirstName 		string `json:"first_name"`
	LastName  		string `json:"last_name"`
	IsEmailVerified bool  `json:"is_email_verified"`
	CreatedAt       time.Time `json:"created_at"`
}

type AuthResponse struct {
	AccessToken    string `json:"access_token"`
	RefreshToken   string `json:"refresh_token"`
	User        UserResponse `json:"user"`
}

type MessageResponse struct {
	Message 		string `json:"message"`
}

type TokenResponse struct {
	AccessToken     string `json:"access_token"`
}

// helper mthd to convert User to UserResponse
func (u *User) ToUserResponse () UserResponse {
	return UserResponse{
		ID: 				fmt.Sprintf("%d", u.ID),
		Email: 				u.Email,
		FirstName: 			u.FirstName,
		LastName: 			u.LastName,
		IsEmailVerified: 	u.IsEmailVerified,
		CreatedAt: 			u.CreatedAt,
	}
}