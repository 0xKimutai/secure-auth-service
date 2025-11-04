# Authentication System

A secure authentication service built with Go and Gin framework, providing JWT-based authentication and user management.

## Features

- User registration and authentication
- JWT-based authentication
- Protected routes
- Password reset functionality
- Email notifications
- PostgreSQL database integration
- Postman collection for API testing

## Prerequisites

- Go 1.25 or higher
- SMTP server credentials for email functionality
- Environment variables configured

## Installation

1. Clone the repository:

```bash
git clone https://github.com/0xKimutai/secure-auth-service.git
cd secure-auth-service
```

2. Install dependencies:

```bash
go mod download
```

3. Configure environment variables:

```bash
cp .env.example .env
```

Edit the `.env` file with your configuration:

```
PORT=8080
JWT_SECRET=your-secret-key
JWT_EXPIRY=24h
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_EMAIL=your-email@gmail.com
SMTP_PASSWORD=your-app-password
FRONTEND_URL=http://localhost:3000
```

## API Endpoints

### Public Routes

- `POST /api/v1/register` - Register a new user
- `POST /api/v1/login` - Authenticate user and receive JWT token
- `POST /api/v1/reset-password` - Request password reset

### Protected Routes (Requires JWT)

- `GET /api/v1/user` - Get user profile
- `PUT /api/v1/user` - Update user profile
- `DELETE /api/v1/user` - Delete user account

## Usage

1. Start the server:

```bash
go run main.go
```

2. The server will start on the configured port (default: 8080)

## API Testing with Postman

### Setting Up Postman

1. Import the collection:

   - Open Postman
   - Click "Import"
   - Select `auth-system.postman_collection.json` from the project root

2. Create an environment:
   - Click "Environments" -> "New"
   - Name it (e.g., "Local Auth System")
   - The collection automatically sets:
     - `base_url`: `http://localhost:8080`
     - `jwt_token`: (set automatically after login)
   - Click "Save"

### Testing Flow

1. **Register a New User**

   - Use "Register User" request
   - Provides example JSON body for registration
   - Returns user profile on success

2. **Login**

   - Use "Login" request with registered credentials
   - Automatically saves JWT token to environment
   - Returns token and user profile

3. **Protected Routes** (requires login first)

   - Get Profile: Fetch user details
   - Update Profile: Modify user information
   - Delete Account: Remove user

4. **Password Reset**
   - Request Reset: Sends reset token via email
   - Confirm Reset: Set new password using token

### Collection Features

- **Public Endpoints** (no auth required)

  - `POST /api/v1/register` - Create account
  - `POST /api/v1/login` - Get JWT token
  - `POST /api/v1/reset-password` - Request reset
  - `POST /api/v1/reset-password/confirm` - Reset password

- **Protected Endpoints** (JWT required)

  - `GET /api/v1/users/me` - Get profile
  - `PUT /api/v1/users/me` - Update profile
  - `DELETE /api/v1/users/me` - Delete account

- **Automatic Token Handling**
  - Login success saves JWT token
  - Protected routes use token automatically
  - Token included in Authorization header

## API Examples

### Register User

```bash
curl -X POST http://localhost:8080/api/v1/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "securepassword123",
    "first_name": "John",
    "last_name": "Doe"
  }'
```

### Login

```bash
curl -X POST http://localhost:8080/api/v1/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "securepassword123"
  }'
```

### Protected Routes

#### Get Profile

```bash
curl -X GET http://localhost:8080/api/v1/users/me \
  -H "Authorization: Bearer your-jwt-token"
```

#### Update Profile

```bash
curl -X PUT http://localhost:8080/api/v1/users/me \
  -H "Authorization: Bearer your-jwt-token" \
  -H "Content-Type: application/json" \
  -d '{
    "first_name": "Updated",
    "last_name": "Name"
  }'
```

## Project Structure

```
.
├── config/
│   └── config.go         # Configuration management
├── controllers/
│   └── auth_controller.go # Authentication handlers
├── middleware/
│   └── auth_middleware.go # JWT authentication middleware
├── models/
│   └── user.go          # User model and DTOs
├── routes/
│   └── routes.go        # Route definitions
├── utils/
│   ├── email.go         # Email utilities
│   ├── jwt.go           # JWT utilities
│   └── password.go      # Password hashing utilities
├── .env                 # Environment variables
├── go.mod              # Go module file
├── go.sum              # Go module checksum
├── main.go            # Application entry point
└── README.md          # This file
```

## Security Features

- Password hashing using bcrypt
- JWT-based authentication
- Secure password reset mechanism
- Email verification support
- Request validation and sanitization

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request
