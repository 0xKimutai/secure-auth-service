package utils

import (
	"authentication-system/config"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"gopkg.in/gomail.v2"
)

// send welcome email
// send verification email
// generate reset password tokwn
// send reset password email

func SendVerificationEmail(toEmail, verificationToken string) error {
	m := gomail.NewMessage()
	m.SetHeader("From", config.AppConfig.SMTPEmail)
	m.SetHeader("To", toEmail)
	m.SetHeader("Subject", "Verify Your Email Address")

	verificationURL := fmt.Sprintf("%s/verify-email?token=%s", config.AppConfig.FrontendURL, verificationToken)

	body := fmt.Sprintf(`
		<html>
		<body>
			<h2>Email verification</h2>
			<p>Thank you for signing up!</p>
			<p>Please verify your email address by clicking the link below</p>
			<p><a href="%s">Verify Email</a></p>
			<p>If you did not create an account, ignore this email</p>
		</body>
		</html>
	`, verificationURL)

	m.SetBody("text/html", body)

	port := 587
	if config.AppConfig.SMTPort != "" {
		fmt.Scanf(config.AppConfig.SMTPort, "%d", &port)
	}

	d := gomail.NewDialer(
		config.AppConfig.SMTPHost,
		port,
		config.AppConfig.SMTPEmail,
		config.AppConfig.SMTPPassword,
	)

	if err := d.DialAndSend(m); err != nil {
		return err
	}
	return nil
}

// send welcome email aafter successful verification
func SendWelcomeEmail(toEmail, firstName string) error {
	m := gomail.NewMessage()
	m.SetHeader("From", config.AppConfig.SMTPEmail)
	m.SetHeader("To", toEmail)
	m.SetHeader("Subject", "Welcome to Our Platform")
	
	body := fmt.Sprintf(`
		<html>
		<body>
			<h2>Welcome, %s!</h2>
			<p>Thank you for signing up<p>
			<p>Your email has been successfuly verified</p>
			<p>Pleasure to have you onboard<p>
		<body>
		<html>
	`, firstName)

	m.SetBody("text/html", body)

	port := 587
	if config.AppConfig.SMTPort != "" {
		fmt.Scanf(config.AppConfig.SMTPort, "%d", port)
	}

	d := gomail.NewDialer(
		config.AppConfig.SMTPHost,
		port,
		config.AppConfig.SMTPEmail,
		config.AppConfig.SMTPPassword,
	)

	if err := d.DialAndSend(m); err != nil {
		return err
	}
	return nil
}

func GenerateResetPasswordToken() (string, error) {
	 bytes := make([]byte, 32)
	 if _, err := rand.Read(bytes); err != nil {
		return "", err
	 }
	 return hex.EncodeToString(bytes), nil
}

func SendResetPasswordEmail(toEmail, resetToken string) error {
	m := gomail.NewMessage()
	m.SetHeader("From", config.AppConfig.SMTPEmail)
	m.SetHeader("To", toEmail)
	m.SetHeader("Subject", "Password reset request")

	resetURL := fmt.Sprintf("%s/reset-password?token=%s", config.AppConfig.FrontendURL, resetToken)

	body := fmt.Sprintf(`
		<html>
		<body>
			<h2>Password reset request</p>
			<p>You requested to reset your password</p>
			<p><a href="%s">Reset Password</a></p>
			<p>This link will expire in 1 hour.</p>
			<p>If you did not request this, please ignore</p>
		</body>
		</html>
	`, resetURL)

	m.SetBody("text/html", body)

	port := 587
	if config.AppConfig.SMTPort != "" {
		fmt.Scanf(config.AppConfig.SMTPort, "%d", &port)
	}

	//dialer &sending
	d := gomail.NewDialer(
		config.AppConfig.SMTPHost,
		port,
		config.AppConfig.SMTPEmail,
		config.AppConfig.SMTPPassword,
	)

	if err := d.DialAndSend(m); err != nil {
		return err
	}

	return nil
}

