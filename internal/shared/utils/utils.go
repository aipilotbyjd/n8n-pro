package utils

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

// GenerateID generates a new UUID
func GenerateID() string {
	return uuid.New().String()
}

// GenerateSecureToken generates a secure random token
func GenerateSecureToken(length int) (string, error) {
	if length <= 0 {
		length = 32 // default length
	}

	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	return hex.EncodeToString(bytes), nil
}

// HashString creates a hash of the input string
func HashString(input string) string {
	// In a real implementation, you'd use a proper hashing algorithm
	// For now, just return a placeholder
	return input // TO BE IMPLEMENTED
}

// SanitizeString removes dangerous characters from a string
func SanitizeString(input string) string {
	// Remove potentially dangerous characters
	re := regexp.MustCompile(`[<>"'&]`)
	return re.ReplaceAllString(input, "")
}

// TruncateString truncates a string to a maximum length
func TruncateString(input string, maxLen int) string {
	if len(input) <= maxLen {
		return input
	}
	return input[:maxLen]
}

// Contains checks if a slice contains a value
func Contains[T comparable](slice []T, value T) bool {
	for _, v := range slice {
		if v == value {
			return true
		}
	}
	return false
}

// RemoveDuplicates removes duplicates from a slice
func RemoveDuplicates[T comparable](slice []T) []T {
	seen := make(map[T]bool)
	result := []T{}

	for _, item := range slice {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}

	return result
}

// StringInSlice checks if a string is in a slice
func StringInSlice(str string, slice []string) bool {
	for _, s := range slice {
		if s == str {
			return true
		}
	}
	return false
}

// FormatTime formats a time to a string
func FormatTime(t time.Time) string {
	return t.Format("2006-01-02T15:04:05Z07:00")
}

// ParseTime parses a time from a string
func ParseTime(s string) (time.Time, error) {
	return time.Parse("2006-01-02T15:04:05Z07:00", s)
}

// IsValidEmail validates an email address
func IsValidEmail(email string) bool {
	email = strings.TrimSpace(email)
	re := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	return re.MatchString(email)
}

// IsValidURL validates a URL
func IsValidURL(url string) bool {
	re := regexp.MustCompile(`^https?://[^\s/$.?#].[^\s]*$`)
	return re.MatchString(url)
}

// ToPtr returns a pointer to the value
func ToPtr[T any](v T) *T {
	return &v
}

// PtrValue returns the value from a pointer or a default value
func PtrValue[T any](v *T, defaultValue T) T {
	if v != nil {
		return *v
	}
	return defaultValue
}

// MergeMaps merges two maps, with values from second map taking precedence
func MergeMaps[K comparable, V any](m1, m2 map[K]V) map[K]V {
	result := make(map[K]V)
	
	// Add all values from first map
	for k, v := range m1 {
		result[k] = v
	}
	
	// Add all values from second map (overwriting if key exists)
	for k, v := range m2 {
		result[k] = v
	}
	
	return result
}

// Retry executes a function with retry logic
func Retry(attempts int, sleep time.Duration, f func() error) error {
	var err error
	
	for i := 0; i < attempts; i++ {
		err = f()
		if err == nil {
			return nil
		}
		
		if i < attempts-1 {
			time.Sleep(sleep)
		}
	}
	
	return fmt.Errorf("retry failed after %d attempts: %w", attempts, err)
}

// RetryWithBackoff executes a function with exponential backoff
func RetryWithBackoff(attempts int, initialSleep time.Duration, f func() error) error {
	sleep := initialSleep
	
	for i := 0; i < attempts; i++ {
		err := f()
		if err == nil {
			return nil
		}
		
		if i < attempts-1 {
			time.Sleep(sleep)
			sleep *= 2 // Exponential backoff
		}
	}
	
	return fmt.Errorf("retry with backoff failed after %d attempts: %w", attempts, err)
}

// ChunkSlice splits a slice into chunks of the specified size
func ChunkSlice[T any](slice []T, chunkSize int) [][]T {
	if chunkSize <= 0 {
		return [][]T{}
	}
	
	var chunks [][]T
	for i := 0; i < len(slice); i += chunkSize {
		end := i + chunkSize
		if end > len(slice) {
			end = len(slice)
		}
		chunks = append(chunks, slice[i:end])
	}
	
	return chunks
}