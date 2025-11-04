package models

import "time"

type ResetToken struct {
	Token     string    `gorm:"primary_key"`
	UserID    uint      `gorm:"not null"`
	Email     string    `gorm:"not null"`
	ExpiresAt time.Time `gorm:"not null"`
	CreatedAt time.Time
	UpdatedAt time.Time
}