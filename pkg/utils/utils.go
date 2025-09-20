package utils

import (
	"bytes"
	"crypto/md5"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"math"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// String utilities

// IsEmpty checks if a string is empty or contains only whitespace
func IsEmpty(s string) bool {
	return strings.TrimSpace(s) == ""
}

// Truncate truncates a string to the specified length
func Truncate(s string, maxLength int) string {
	if len(s) <= maxLength {
		return s
	}
	if maxLength <= 3 {
		return s[:maxLength]
	}
	return s[:maxLength-3] + "..."
}

// ToCamelCase converts a string to camelCase
func ToCamelCase(s string) string {
	if s == "" {
		return s
	}

	words := strings.FieldsFunc(s, func(c rune) bool {
		return c == '_' || c == '-' || c == ' '
	})

	if len(words) == 0 {
		return s
	}

	result := strings.ToLower(words[0])
	for i := 1; i < len(words); i++ {
		if len(words[i]) > 0 {
			result += strings.ToUpper(words[i][:1]) + strings.ToLower(words[i][1:])
		}
	}

	return result
}

// ToSnakeCase converts a string to snake_case
func ToSnakeCase(s string) string {
	var result strings.Builder
	for i, r := range s {
		if i > 0 && (r >= 'A' && r <= 'Z') {
			result.WriteRune('_')
		}
		result.WriteRune(r)
	}
	return strings.ToLower(result.String())
}

// SanitizeFilename removes or replaces invalid characters from filenames
func SanitizeFilename(filename string) string {
	// Replace invalid characters with underscores
	invalidChars := regexp.MustCompile(`[<>:"/\\|?*]`)
	sanitized := invalidChars.ReplaceAllString(filename, "_")

	// Remove leading/trailing dots and spaces
	sanitized = strings.Trim(sanitized, ". ")

	// Limit length
	if len(sanitized) > 255 {
		sanitized = sanitized[:255]
	}

	return sanitized
}

// Reverse reverses a string
func Reverse(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

// JSON utilities

// JSONPath extracts a value from JSON using a dot-notation path
func JSONPath(data interface{}, path string) (interface{}, error) {
	if path == "" {
		return data, nil
	}

	parts := strings.Split(path, ".")
	current := data

	for _, part := range parts {
		switch v := current.(type) {
		case map[string]interface{}:
			if val, exists := v[part]; exists {
				current = val
			} else {
				return nil, fmt.Errorf("path not found: %s", part)
			}
		case []interface{}:
			index, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid array index: %s", part)
			}
			if index < 0 || index >= len(v) {
				return nil, fmt.Errorf("array index out of bounds: %d", index)
			}
			current = v[index]
		default:
			return nil, fmt.Errorf("cannot traverse into non-object/array: %T", current)
		}
	}

	return current, nil
}

// JSONMerge deeply merges two JSON objects
func JSONMerge(dst, src map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})

	// Copy dst
	for k, v := range dst {
		result[k] = v
	}

	// Merge src
	for k, v := range src {
		if existing, exists := result[k]; exists {
			if existingMap, ok := existing.(map[string]interface{}); ok {
				if srcMap, ok := v.(map[string]interface{}); ok {
					result[k] = JSONMerge(existingMap, srcMap)
					continue
				}
			}
		}
		result[k] = v
	}

	return result
}

// PrettyJSON formats JSON with indentation
func PrettyJSON(v interface{}) (string, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// CompactJSON removes whitespace from JSON
func CompactJSON(jsonStr string) (string, error) {
	var buf bytes.Buffer
	err := json.Compact(&buf, []byte(jsonStr))
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}

// HTTP utilities

// ParseQuery safely parses URL query parameters
func ParseQuery(rawQuery string) (map[string]string, error) {
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return nil, err
	}

	result := make(map[string]string)
	for key, vals := range values {
		if len(vals) > 0 {
			result[key] = vals[0]
		}
	}

	return result, nil
}

// BuildQuery builds a query string from a map
func BuildQuery(params map[string]string) string {
	values := make(url.Values)
	for key, value := range params {
		values.Set(key, value)
	}
	return values.Encode()
}

// ExtractBearerToken extracts bearer token from Authorization header
func ExtractBearerToken(authHeader string) string {
	if strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimPrefix(authHeader, "Bearer ")
	}
	return ""
}

// GetClientIP extracts client IP from request headers
func GetClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		ips := strings.Split(xff, ",")
		return strings.TrimSpace(ips[0])
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to remote address
	ip := r.RemoteAddr
	if colon := strings.LastIndex(ip, ":"); colon != -1 {
		ip = ip[:colon]
	}

	return ip
}

// Time utilities

// FormatDuration formats a duration in human-readable format
func FormatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	if d < time.Hour {
		return fmt.Sprintf("%.1fm", d.Minutes())
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%.1fh", d.Hours())
	}
	return fmt.Sprintf("%.1fd", d.Hours()/24)
}

// ParseDuration parses a duration string with support for additional units
func ParseDuration(s string) (time.Duration, error) {
	// Try standard parsing first
	if d, err := time.ParseDuration(s); err == nil {
		return d, nil
	}

	// Handle custom formats
	if strings.HasSuffix(s, "d") {
		days, err := strconv.ParseFloat(strings.TrimSuffix(s, "d"), 64)
		if err != nil {
			return 0, err
		}
		return time.Duration(days * 24 * float64(time.Hour)), nil
	}

	return 0, fmt.Errorf("invalid duration format: %s", s)
}

// StartOfDay returns the start of the day for the given time
func StartOfDay(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, t.Location())
}

// EndOfDay returns the end of the day for the given time
func EndOfDay(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), t.Day(), 23, 59, 59, 999999999, t.Location())
}

// Crypto utilities

// GenerateHash generates a SHA-256 hash of the input
func GenerateHash(input string) string {
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:])
}

// GenerateMD5 generates an MD5 hash of the input
func GenerateMD5(input string) string {
	hash := md5.Sum([]byte(input))
	return hex.EncodeToString(hash[:])
}

// GenerateRandomString generates a random string of specified length
func GenerateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

// EncodeBase64 encodes data to base64
func EncodeBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// DecodeBase64 decodes base64 data
func DecodeBase64(encoded string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(encoded)
}

// File utilities

// FileExists checks if a file exists
func FileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

// DirExists checks if a directory exists
func DirExists(dirname string) bool {
	info, err := os.Stat(dirname)
	if os.IsNotExist(err) {
		return false
	}
	return info.IsDir()
}

// EnsureDir creates a directory if it doesn't exist
func EnsureDir(dirname string) error {
	if !DirExists(dirname) {
		return os.MkdirAll(dirname, 0755)
	}
	return nil
}

// ReadFileLines reads a file and returns lines as a slice
func ReadFileLines(filename string) ([]string, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(content), "\n")
	// Remove last empty line if exists
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}

	return lines, nil
}

// WriteFileAtomic writes data to a file atomically
func WriteFileAtomic(filename string, data []byte) error {
	tempFile := filename + ".tmp"

	if err := os.WriteFile(tempFile, data, 0644); err != nil {
		return err
	}

	return os.Rename(tempFile, filename)
}

// GetFileSize returns the size of a file in bytes
func GetFileSize(filename string) (int64, error) {
	info, err := os.Stat(filename)
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

// Validation utilities

// IsValidEmail validates an email address
func IsValidEmail(email string) bool {
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	return emailRegex.MatchString(email)
}

// IsValidURL validates a URL
func IsValidURL(rawURL string) bool {
	_, err := url.ParseRequestURI(rawURL)
	return err == nil
}

// IsValidUUID validates a UUID string
func IsValidUUID(uuidStr string) bool {
	_, err := uuid.Parse(uuidStr)
	return err == nil
}

// IsValidJSON checks if a string is valid JSON
func IsValidJSON(jsonStr string) bool {
	var js json.RawMessage
	return json.Unmarshal([]byte(jsonStr), &js) == nil
}

// Collection utilities

// Contains checks if a slice contains a specific value
func Contains[T comparable](slice []T, item T) bool {
	for _, v := range slice {
		if v == item {
			return true
		}
	}
	return false
}

// Unique removes duplicates from a slice
func Unique[T comparable](slice []T) []T {
	keys := make(map[T]bool)
	var result []T

	for _, item := range slice {
		if !keys[item] {
			keys[item] = true
			result = append(result, item)
		}
	}

	return result
}

// Filter filters a slice based on a predicate function
func Filter[T any](slice []T, predicate func(T) bool) []T {
	var result []T
	for _, item := range slice {
		if predicate(item) {
			result = append(result, item)
		}
	}
	return result
}

// Map applies a function to each element of a slice
func Map[T, R any](slice []T, fn func(T) R) []R {
	result := make([]R, len(slice))
	for i, item := range slice {
		result[i] = fn(item)
	}
	return result
}

// Reduce reduces a slice to a single value using a function
func Reduce[T, R any](slice []T, initial R, fn func(R, T) R) R {
	result := initial
	for _, item := range slice {
		result = fn(result, item)
	}
	return result
}

// Chunk splits a slice into chunks of specified size
func Chunk[T any](slice []T, size int) [][]T {
	if size <= 0 {
		return [][]T{slice}
	}

	var chunks [][]T
	for i := 0; i < len(slice); i += size {
		end := i + size
		if end > len(slice) {
			end = len(slice)
		}
		chunks = append(chunks, slice[i:end])
	}

	return chunks
}

// MapKeys extracts keys from a map
func MapKeys[K comparable, V any](m map[K]V) []K {
	keys := make([]K, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// MapValues extracts values from a map
func MapValues[K comparable, V any](m map[K]V) []V {
	values := make([]V, 0, len(m))
	for _, v := range m {
		values = append(values, v)
	}
	return values
}

// Template utilities

// RenderTemplate renders a text template with data
func RenderTemplate(templateStr string, data interface{}) (string, error) {
	tmpl, err := template.New("template").Parse(templateStr)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}

	return buf.String(), nil
}

// RenderTemplateWithFuncs renders a template with custom functions
func RenderTemplateWithFuncs(templateStr string, data interface{}, funcs template.FuncMap) (string, error) {
	tmpl, err := template.New("template").Funcs(funcs).Parse(templateStr)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}

	return buf.String(), nil
}

// ID generation utilities

// GenerateUUID generates a new UUID
func GenerateUUID() string {
	return uuid.New().String()
}

// GenerateShortID generates a short alphanumeric ID
func GenerateShortID(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	return GenerateRandomStringFromCharset(length, charset)
}

// GenerateRandomStringFromCharset generates a random string from a custom charset
func GenerateRandomStringFromCharset(length int, charset string) string {
	b := make([]byte, length)
	charsetLen := len(charset)

	for i := range b {
		randomBytes := make([]byte, 1)
		cryptorand.Read(randomBytes)
		b[i] = charset[randomBytes[0]%byte(charsetLen)]
	}

	return string(b)
}

// Configuration utilities

// GetEnv gets an environment variable with a default value
func GetEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// GetEnvInt gets an integer environment variable with a default value
func GetEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

// GetEnvBool gets a boolean environment variable with a default value
func GetEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}

// GetEnvDuration gets a duration environment variable with a default value
func GetEnvDuration(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if duration, err := ParseDuration(value); err == nil {
			return duration
		}
	}
	return defaultValue
}

// Pagination utilities

// PaginationInfo holds pagination metadata
type PaginationInfo struct {
	Page       int  `json:"page"`
	PageSize   int  `json:"page_size"`
	TotalCount int  `json:"total_count"`
	TotalPages int  `json:"total_pages"`
	HasNext    bool `json:"has_next"`
	HasPrev    bool `json:"has_prev"`
}

// CalculatePagination calculates pagination metadata
func CalculatePagination(page, pageSize, totalCount int) PaginationInfo {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 10
	}

	totalPages := int(math.Ceil(float64(totalCount) / float64(pageSize)))
	if totalPages < 1 {
		totalPages = 1
	}

	return PaginationInfo{
		Page:       page,
		PageSize:   pageSize,
		TotalCount: totalCount,
		TotalPages: totalPages,
		HasNext:    page < totalPages,
		HasPrev:    page > 1,
	}
}

// CalculateOffset calculates the offset for database queries
func CalculateOffset(page, pageSize int) int {
	if page < 1 {
		page = 1
	}
	return (page - 1) * pageSize
}

// Math utilities

// MinInt returns the minimum of two integers
func MinInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// MaxInt returns the maximum of two integers
func MaxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// ClampInt clamps an integer between min and max values
func ClampInt(value, min, max int) int {
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

// RoundFloat rounds a float to the specified number of decimal places
func RoundFloat(value float64, places int) float64 {
	multiplier := math.Pow(10, float64(places))
	return math.Round(value*multiplier) / multiplier
}

// Reflection utilities

// GetStructFieldNames returns the names of struct fields
func GetStructFieldNames(v interface{}) []string {
	var names []string
	val := reflect.ValueOf(v)

	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}

	if val.Kind() != reflect.Struct {
		return names
	}

	typ := val.Type()
	for i := 0; i < val.NumField(); i++ {
		field := typ.Field(i)
		if field.IsExported() {
			names = append(names, field.Name)
		}
	}

	return names
}

// IsZero checks if a value is the zero value for its type
func IsZero(v interface{}) bool {
	if v == nil {
		return true
	}
	return reflect.DeepEqual(v, reflect.Zero(reflect.TypeOf(v)).Interface())
}

// Miscellaneous utilities

// Retry executes a function with simple retry logic
func SimpleRetry(attempts int, delay time.Duration, fn func() error) error {
	var err error
	for i := 0; i < attempts; i++ {
		if err = fn(); err == nil {
			return nil
		}
		if i < attempts-1 {
			time.Sleep(delay)
		}
	}
	return err
}

// Debounce creates a debounced function
func Debounce(delay time.Duration, fn func()) func() {
	var timer *time.Timer
	return func() {
		if timer != nil {
			timer.Stop()
		}
		timer = time.AfterFunc(delay, fn)
	}
}

// SortStringSlice sorts a string slice and returns it
func SortStringSlice(slice []string) []string {
	sorted := make([]string, len(slice))
	copy(sorted, slice)
	sort.Strings(sorted)
	return sorted
}

// JoinNonEmpty joins non-empty strings with a separator
func JoinNonEmpty(sep string, strs ...string) string {
	var nonEmpty []string
	for _, s := range strs {
		if s != "" {
			nonEmpty = append(nonEmpty, s)
		}
	}
	return strings.Join(nonEmpty, sep)
}

// CopyFile copies a file from src to dst
func CopyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	return err
}

// AbsolutePath returns the absolute path of a file
func AbsolutePath(path string) (string, error) {
	return filepath.Abs(path)
}

// RelativePath returns the relative path between two paths
func RelativePath(basepath, targpath string) (string, error) {
	return filepath.Rel(basepath, targpath)
}
