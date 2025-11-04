package config

import (
	"log"
	"os"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	Port               string
	DBHost             string
	DBPort             string
	DBUser             string
	DBPassword         string
	DBName             string
	JWTSecret          string
	JWTExpiry          time.Duration
	RefreshTokenExpiry time.Duration
	SMTPHost           string
	SMTPort            string
	SMTPEmail          string
	SMTPPassword       string
	FrontendURL        string
}

var AppConfig *Config

func init() {
	// load environment variables from .env file
	loadConfig()
}

func loadConfig() () {
	err := godotenv.Load()
	if err != nil {
		log.Println(".env file not found!")
	}

	// parsing duration values
	jwtExpiry, err := time.ParseDuration(getEnv("JWT_EXPIRY", "24h"))

	if err != nil {
		jwtExpiry = 24 * time.Hour
		log.Printf("Invalid JWT_EXPIRY format, using using default %v\n", jwtExpiry)
	}

	// parse refresh token expiry (default 7 days)
	refreshExpiry, err := time.ParseDuration(getEnv("REFRESH_TOKEN_EXPIRY", "168h"))
	if err != nil {
		refreshExpiry = 7 * 24 * time.Hour
		log.Printf("Invalid REFRESH_TOKEN_EXPIRY format, using default %v\n", refreshExpiry)
	}

	// creating the config instance
	AppConfig = &Config{
		Port:               getEnv("PORT", "8080"),
		DBHost:             getEnv("DB_HOST", "localhost"),
		DBPort:             getEnv("DB_PORT", "5432"),
		DBUser:             getEnv("DB_USER", "postgres"),
		DBPassword:         getEnv("DB_PASSWORD", "password"),
		DBName:             getEnv("DB_NAME", "auth_db"),
		JWTSecret:          getEnv("JWT_SECRET", "your-super-secret-key-change-this-in-production"),
		JWTExpiry:          jwtExpiry,
		RefreshTokenExpiry: refreshExpiry,
		SMTPHost:           getEnv("SMTP_HOST", "smtp.gmail.com"),
		SMTPort:            getEnv("SMTP_PORT", "587"),
		SMTPEmail:          getEnv("SMTP_EMAIL", ""),
		SMTPPassword:       getEnv("SMTP_PASSWORD", ""),
		FrontendURL:        getEnv("FRONTEND_URL", "http://localhost:3000"),
	}
}



func getEnv (key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}