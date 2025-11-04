package utils

import (
	"authentication-system/config"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// claims structure
// generate access tokens
// generate refresh tokens
// validate token
// validate refresh token

type Claims struct {
	UserID uint    `json:"user_id"`
	Email  string   `json:"email"`
	jwt.RegisteredClaims
}

// generate access tokens
func GenerateAccessToken(userID uint, email string) (string, error) {
	// create the claims
	claims := Claims{
		UserID: userID,
		Email: email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(config.AppConfig.JWTExpiry)),
			IssuedAt: jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(config.AppConfig.JWTSecret))
}

// generate refresh tokens
func GenerateRefreshToken(userID uint) (string, error) {
	claims := jwt.RegisteredClaims{
		Subject: string(rune(userID)), // store user id in subject
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(config.AppConfig.JWTExpiry)),
		IssuedAt: jwt.NewNumericDate(time.Now()),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(config.AppConfig.JWTSecret))
}

// validate and pass token
func ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("Invalid Signing Method")
		}
		return []byte(config.AppConfig.JWTSecret), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}
	return nil, errors.New("Invalid token")
}

// validate refresh token
func ValidateRefeshToken (tokenString string) (uint, error) {
	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func (token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("Invalid Signing Method")
		}
		return []byte (config.AppConfig.JWTSecret), nil
	})

	if err != nil {
		return 0, err
	}

	if claims, ok := token.Claims.(*jwt.RegisteredClaims); ok && token.Valid {
		// extract user id from subject
		userID := uint(claims.Subject[0])
		return userID, nil
	}
	return 0, errors.New("Invalid refresh token")
}