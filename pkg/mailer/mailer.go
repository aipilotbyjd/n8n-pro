package mailer

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"html/template"
	"net/smtp"
	"strings"
	"time"

	"n8n-pro/pkg/logger"
)

// Mailer interface defines email operations
type Mailer interface {
	Send(ctx context.Context, email *Email) error
	SendTemplate(ctx context.Context, to string, templateName string, data interface{}) error
	SendBulk(ctx context.Context, emails []*Email) error
}

// Email represents an email message
type Email struct {
	From        string
	To          []string
	CC          []string
	BCC         []string
	ReplyTo     string
	Subject     string
	Text        string
	HTML        string
	Attachments []*Attachment
	Headers     map[string]string
	Priority    Priority
	RetryCount  int
}

// Attachment represents an email attachment
type Attachment struct {
	Filename    string
	ContentType string
	Content     []byte
	Inline      bool
	ContentID   string
}

// Priority represents email priority
type Priority int

const (
	PriorityLow Priority = iota
	PriorityNormal
	PriorityHigh
	PriorityUrgent
)

// Config contains mailer configuration
type Config struct {
	// SMTP configuration
	SMTPHost     string `json:"smtp_host"`
	SMTPPort     int    `json:"smtp_port"`
	SMTPUser     string `json:"smtp_user"`
	SMTPPassword string `json:"smtp_password"`
	SMTPFrom     string `json:"smtp_from"`
	SMTPFromName string `json:"smtp_from_name"`
	
	// TLS configuration
	EnableTLS    bool   `json:"enable_tls"`
	SkipVerify   bool   `json:"skip_verify"`
	
	// SendGrid configuration (alternative)
	SendGridAPIKey string `json:"sendgrid_api_key"`
	
	// General settings
	MaxRetries   int           `json:"max_retries"`
	RetryDelay   time.Duration `json:"retry_delay"`
	SendTimeout  time.Duration `json:"send_timeout"`
	TemplateDir  string        `json:"template_dir"`
	
	// Rate limiting
	RateLimit    int           `json:"rate_limit"` // emails per minute
	BulkSize     int           `json:"bulk_size"`
	
	// Development settings
	DevMode      bool          `json:"dev_mode"`
	DevEmail     string        `json:"dev_email"` // Redirect all emails here in dev mode
}

// SMTPMailer implements Mailer using SMTP
type SMTPMailer struct {
	config    *Config
	templates map[string]*template.Template
	logger    logger.Logger
}

// NewSMTPMailer creates a new SMTP mailer
func NewSMTPMailer(config *Config) (*SMTPMailer, error) {
	mailer := &SMTPMailer{
		config:    config,
		templates: make(map[string]*template.Template),
		logger:    logger.New("smtp-mailer"),
	}
	
	// Load email templates
	if err := mailer.loadTemplates(); err != nil {
		return nil, fmt.Errorf("failed to load email templates: %w", err)
	}
	
	return mailer, nil
}

// Send sends a single email
func (m *SMTPMailer) Send(ctx context.Context, email *Email) error {
	// In development mode, redirect to dev email
	if m.config.DevMode && m.config.DevEmail != "" {
		email.To = []string{m.config.DevEmail}
		email.CC = nil
		email.BCC = nil
		m.logger.Info("Dev mode: redirecting email", "original_to", email.To, "dev_email", m.config.DevEmail)
	}
	
	// Build message
	msg := m.buildMessage(email)
	
	// Send with retry logic
	var lastErr error
	for i := 0; i <= m.config.MaxRetries; i++ {
		if err := m.sendSMTP(email.To, msg); err != nil {
			lastErr = err
			m.logger.Error("Failed to send email", "attempt", i+1, "error", err)
			
			if i < m.config.MaxRetries {
				time.Sleep(m.config.RetryDelay * time.Duration(i+1))
				continue
			}
		} else {
			m.logger.Info("Email sent successfully", "to", email.To, "subject", email.Subject)
			return nil
		}
	}
	
	return fmt.Errorf("failed to send email after %d attempts: %w", m.config.MaxRetries+1, lastErr)
}

// SendTemplate sends an email using a template
func (m *SMTPMailer) SendTemplate(ctx context.Context, to string, templateName string, data interface{}) error {
	tmpl, exists := m.templates[templateName]
	if !exists {
		return fmt.Errorf("template %s not found", templateName)
	}
	
	// Execute template for subject
	var subjectBuf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&subjectBuf, "subject", data); err != nil {
		return fmt.Errorf("failed to execute subject template: %w", err)
	}
	
	// Execute template for HTML body
	var htmlBuf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&htmlBuf, "html", data); err != nil {
		return fmt.Errorf("failed to execute HTML template: %w", err)
	}
	
	// Execute template for text body
	var textBuf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&textBuf, "text", data); err != nil {
		// Text template is optional
		textBuf.WriteString(stripHTML(htmlBuf.String()))
	}
	
	email := &Email{
		From:    m.getFromAddress(),
		To:      []string{to},
		Subject: subjectBuf.String(),
		HTML:    htmlBuf.String(),
		Text:    textBuf.String(),
		Headers: map[string]string{
			"X-Template": templateName,
		},
	}
	
	return m.Send(ctx, email)
}

// SendBulk sends multiple emails
func (m *SMTPMailer) SendBulk(ctx context.Context, emails []*Email) error {
	if len(emails) == 0 {
		return nil
	}
	
	// Process in batches
	batchSize := m.config.BulkSize
	if batchSize <= 0 {
		batchSize = 10
	}
	
	var errors []error
	for i := 0; i < len(emails); i += batchSize {
		end := i + batchSize
		if end > len(emails) {
			end = len(emails)
		}
		
		batch := emails[i:end]
		for _, email := range batch {
			if err := m.Send(ctx, email); err != nil {
				errors = append(errors, fmt.Errorf("failed to send to %v: %w", email.To, err))
			}
			
			// Rate limiting
			if m.config.RateLimit > 0 {
				delay := time.Minute / time.Duration(m.config.RateLimit)
				time.Sleep(delay)
			}
		}
	}
	
	if len(errors) > 0 {
		return fmt.Errorf("bulk send completed with %d errors", len(errors))
	}
	
	return nil
}

// Helper methods

func (m *SMTPMailer) sendSMTP(to []string, msg []byte) error {
	auth := smtp.PlainAuth("", m.config.SMTPUser, m.config.SMTPPassword, m.config.SMTPHost)
	
	addr := fmt.Sprintf("%s:%d", m.config.SMTPHost, m.config.SMTPPort)
	
	if m.config.EnableTLS {
		return m.sendSMTPWithTLS(addr, auth, m.config.SMTPFrom, to, msg)
	}
	
	return smtp.SendMail(addr, auth, m.config.SMTPFrom, to, msg)
}

func (m *SMTPMailer) sendSMTPWithTLS(addr string, auth smtp.Auth, from string, to []string, msg []byte) error {
	client, err := smtp.Dial(addr)
	if err != nil {
		return err
	}
	defer client.Close()
	
	// Start TLS
	tlsConfig := &tls.Config{
		ServerName:         m.config.SMTPHost,
		InsecureSkipVerify: m.config.SkipVerify,
	}
	
	if err := client.StartTLS(tlsConfig); err != nil {
		return err
	}
	
	// Authenticate
	if err := client.Auth(auth); err != nil {
		return err
	}
	
	// Set sender and recipients
	if err := client.Mail(from); err != nil {
		return err
	}
	
	for _, recipient := range to {
		if err := client.Rcpt(recipient); err != nil {
			return err
		}
	}
	
	// Send the email body
	w, err := client.Data()
	if err != nil {
		return err
	}
	
	_, err = w.Write(msg)
	if err != nil {
		return err
	}
	
	err = w.Close()
	if err != nil {
		return err
	}
	
	return client.Quit()
}

func (m *SMTPMailer) buildMessage(email *Email) []byte {
	var msg bytes.Buffer
	
	// Headers
	msg.WriteString(fmt.Sprintf("From: %s\r\n", email.From))
	msg.WriteString(fmt.Sprintf("To: %s\r\n", strings.Join(email.To, ", ")))
	
	if len(email.CC) > 0 {
		msg.WriteString(fmt.Sprintf("Cc: %s\r\n", strings.Join(email.CC, ", ")))
	}
	
	if email.ReplyTo != "" {
		msg.WriteString(fmt.Sprintf("Reply-To: %s\r\n", email.ReplyTo))
	}
	
	msg.WriteString(fmt.Sprintf("Subject: %s\r\n", email.Subject))
	msg.WriteString(fmt.Sprintf("Date: %s\r\n", time.Now().Format(time.RFC1123Z)))
	
	// Priority
	if email.Priority == PriorityHigh || email.Priority == PriorityUrgent {
		msg.WriteString("X-Priority: 1\r\n")
		msg.WriteString("X-MSMail-Priority: High\r\n")
	}
	
	// Custom headers
	for key, value := range email.Headers {
		msg.WriteString(fmt.Sprintf("%s: %s\r\n", key, value))
	}
	
	// MIME headers for multipart
	boundary := "boundary-" + fmt.Sprintf("%d", time.Now().UnixNano())
	msg.WriteString("MIME-Version: 1.0\r\n")
	msg.WriteString(fmt.Sprintf("Content-Type: multipart/alternative; boundary=\"%s\"\r\n", boundary))
	msg.WriteString("\r\n")
	
	// Text part
	if email.Text != "" {
		msg.WriteString(fmt.Sprintf("--%s\r\n", boundary))
		msg.WriteString("Content-Type: text/plain; charset=\"utf-8\"\r\n")
		msg.WriteString("Content-Transfer-Encoding: quoted-printable\r\n")
		msg.WriteString("\r\n")
		msg.WriteString(email.Text)
		msg.WriteString("\r\n")
	}
	
	// HTML part
	if email.HTML != "" {
		msg.WriteString(fmt.Sprintf("--%s\r\n", boundary))
		msg.WriteString("Content-Type: text/html; charset=\"utf-8\"\r\n")
		msg.WriteString("Content-Transfer-Encoding: quoted-printable\r\n")
		msg.WriteString("\r\n")
		msg.WriteString(email.HTML)
		msg.WriteString("\r\n")
	}
	
	// End boundary
	msg.WriteString(fmt.Sprintf("--%s--\r\n", boundary))
	
	return msg.Bytes()
}

func (m *SMTPMailer) getFromAddress() string {
	if m.config.SMTPFromName != "" {
		return fmt.Sprintf("%s <%s>", m.config.SMTPFromName, m.config.SMTPFrom)
	}
	return m.config.SMTPFrom
}

func (m *SMTPMailer) loadTemplates() error {
	// This would load templates from the file system
	// For now, we'll create them programmatically
	
	// Email verification template
	m.templates["email_verification"] = m.createVerificationTemplate()
	
	// Password reset template
	m.templates["password_reset"] = m.createPasswordResetTemplate()
	
	// Security alert template
	m.templates["security_alert"] = m.createSecurityAlertTemplate()
	
	// MFA code template
	m.templates["mfa_code"] = m.createMFACodeTemplate()
	
	return nil
}

func (m *SMTPMailer) createVerificationTemplate() *template.Template {
	const tmpl = `
{{define "subject"}}Verify your email address{{end}}

{{define "html"}}
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: #007bff; color: white; padding: 20px; text-align: center; }
        .content { padding: 20px; background: #f9f9f9; }
        .button { display: inline-block; padding: 10px 20px; background: #007bff; color: white; text-decoration: none; border-radius: 5px; }
        .footer { text-align: center; padding: 20px; color: #666; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Verify Your Email</h1>
        </div>
        <div class="content">
            <p>Hi {{.FirstName}},</p>
            <p>Thank you for signing up! Please verify your email address by clicking the button below:</p>
            <p style="text-align: center;">
                <a href="{{.VerificationURL}}" class="button">Verify Email</a>
            </p>
            <p>Or copy and paste this link into your browser:</p>
            <p>{{.VerificationURL}}</p>
            <p>This link will expire in 24 hours.</p>
            <p>If you didn't sign up for an account, please ignore this email.</p>
        </div>
        <div class="footer">
            <p>&copy; 2024 n8n Pro. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
{{end}}

{{define "text"}}
Hi {{.FirstName}},

Thank you for signing up! Please verify your email address by visiting:

{{.VerificationURL}}

This link will expire in 24 hours.

If you didn't sign up for an account, please ignore this email.

© 2024 n8n Pro. All rights reserved.
{{end}}
`
	return template.Must(template.New("email_verification").Parse(tmpl))
}

func (m *SMTPMailer) createPasswordResetTemplate() *template.Template {
	const tmpl = `
{{define "subject"}}Reset your password{{end}}

{{define "html"}}
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: #dc3545; color: white; padding: 20px; text-align: center; }
        .content { padding: 20px; background: #f9f9f9; }
        .button { display: inline-block; padding: 10px 20px; background: #dc3545; color: white; text-decoration: none; border-radius: 5px; }
        .footer { text-align: center; padding: 20px; color: #666; font-size: 12px; }
        .warning { background: #fff3cd; padding: 10px; border-left: 4px solid #ffc107; margin: 10px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Password Reset Request</h1>
        </div>
        <div class="content">
            <p>Hi {{.FirstName}},</p>
            <p>We received a request to reset your password. Click the button below to create a new password:</p>
            <p style="text-align: center;">
                <a href="{{.ResetURL}}" class="button">Reset Password</a>
            </p>
            <p>Or copy and paste this link into your browser:</p>
            <p>{{.ResetURL}}</p>
            <div class="warning">
                <strong>Security Notice:</strong> This link will expire in 1 hour. If you didn't request this password reset, please ignore this email and your password will remain unchanged.
            </div>
            <p>For security reasons, we recommend:</p>
            <ul>
                <li>Using a strong, unique password</li>
                <li>Enabling two-factor authentication</li>
                <li>Never sharing your password with anyone</li>
            </ul>
        </div>
        <div class="footer">
            <p>&copy; 2024 n8n Pro. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
{{end}}

{{define "text"}}
Hi {{.FirstName}},

We received a request to reset your password. Visit the link below to create a new password:

{{.ResetURL}}

This link will expire in 1 hour.

Security Notice: If you didn't request this password reset, please ignore this email and your password will remain unchanged.

© 2024 n8n Pro. All rights reserved.
{{end}}
`
	return template.Must(template.New("password_reset").Parse(tmpl))
}

func (m *SMTPMailer) createSecurityAlertTemplate() *template.Template {
	const tmpl = `
{{define "subject"}}Security Alert: {{.AlertType}}{{end}}

{{define "html"}}
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: #ffc107; color: #333; padding: 20px; text-align: center; }
        .content { padding: 20px; background: #f9f9f9; }
        .alert { background: #fff3cd; padding: 15px; border-left: 4px solid #ffc107; margin: 15px 0; }
        .footer { text-align: center; padding: 20px; color: #666; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Security Alert</h1>
        </div>
        <div class="content">
            <p>Hi {{.FirstName}},</p>
            <div class="alert">
                <strong>{{.AlertType}}</strong>
                <p>{{.AlertMessage}}</p>
            </div>
            <p><strong>Details:</strong></p>
            <ul>
                <li>Time: {{.Time}}</li>
                <li>IP Address: {{.IPAddress}}</li>
                <li>Location: {{.Location}}</li>
                <li>Device: {{.Device}}</li>
            </ul>
            <p>If this was you, you can safely ignore this email. If you don't recognize this activity, please:</p>
            <ol>
                <li>Change your password immediately</li>
                <li>Review your account activity</li>
                <li>Enable two-factor authentication</li>
                <li>Contact support if you need assistance</li>
            </ol>
        </div>
        <div class="footer">
            <p>&copy; 2024 n8n Pro. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
{{end}}

{{define "text"}}
Hi {{.FirstName}},

Security Alert: {{.AlertType}}

{{.AlertMessage}}

Details:
- Time: {{.Time}}
- IP Address: {{.IPAddress}}
- Location: {{.Location}}
- Device: {{.Device}}

If this was you, you can safely ignore this email. If you don't recognize this activity, please change your password immediately and contact support.

© 2024 n8n Pro. All rights reserved.
{{end}}
`
	return template.Must(template.New("security_alert").Parse(tmpl))
}

func (m *SMTPMailer) createMFACodeTemplate() *template.Template {
	const tmpl = `
{{define "subject"}}Your verification code: {{.Code}}{{end}}

{{define "html"}}
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: #28a745; color: white; padding: 20px; text-align: center; }
        .content { padding: 20px; background: #f9f9f9; }
        .code { font-size: 32px; font-weight: bold; text-align: center; padding: 20px; background: white; border: 2px dashed #28a745; margin: 20px 0; }
        .footer { text-align: center; padding: 20px; color: #666; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Verification Code</h1>
        </div>
        <div class="content">
            <p>Hi {{.FirstName}},</p>
            <p>Your verification code is:</p>
            <div class="code">{{.Code}}</div>
            <p>This code will expire in {{.ExpiryMinutes}} minutes.</p>
            <p><strong>Security tip:</strong> Never share this code with anyone. Our team will never ask for it.</p>
        </div>
        <div class="footer">
            <p>&copy; 2024 n8n Pro. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
{{end}}

{{define "text"}}
Hi {{.FirstName}},

Your verification code is: {{.Code}}

This code will expire in {{.ExpiryMinutes}} minutes.

Security tip: Never share this code with anyone. Our team will never ask for it.

© 2024 n8n Pro. All rights reserved.
{{end}}
`
	return template.Must(template.New("mfa_code").Parse(tmpl))
}

// stripHTML removes HTML tags from string
func stripHTML(s string) string {
	// Simple HTML stripping - in production use a proper HTML parser
	s = strings.ReplaceAll(s, "<br>", "\n")
	s = strings.ReplaceAll(s, "<br/>", "\n")
	s = strings.ReplaceAll(s, "<br />", "\n")
	s = strings.ReplaceAll(s, "</p>", "\n\n")
	
	// Remove all other tags
	for strings.Contains(s, "<") && strings.Contains(s, ">") {
		start := strings.Index(s, "<")
		end := strings.Index(s, ">")
		if start < end {
			s = s[:start] + s[end+1:]
		} else {
			break
		}
	}
	
	return strings.TrimSpace(s)
}