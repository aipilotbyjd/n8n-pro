package local

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"n8n-pro/pkg/logger"
)

// Storage provides local file storage functionality
type Storage struct {
	basePath string
	logger   logger.Logger
}

// New creates a new local storage instance
func New(basePath string, logger logger.Logger) (*Storage, error) {
	if logger == nil {
		logger = logger.New("local-storage")
	}

	// Ensure base path exists
	if err := os.MkdirAll(basePath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create base path %s: %w", basePath, err)
	}

	storage := &Storage{
		basePath: basePath,
		logger:   logger,
	}

	return storage, nil
}

// Save saves data to the local file system
func (s *Storage) Save(ctx context.Context, key string, data []byte) error {
	// Sanitize the key to prevent directory traversal
	sanitizedKey := s.sanitizeKey(key)
	if sanitizedKey == "" {
		return fmt.Errorf("invalid key")
	}

	fullPath := filepath.Join(s.basePath, sanitizedKey)

	// Create directory if it doesn't exist
	dir := filepath.Dir(fullPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		s.logger.Error("Failed to create directory", "path", dir, "error", err)
		return err
	}

	// Write data to file
	if err := os.WriteFile(fullPath, data, 0644); err != nil {
		s.logger.Error("Failed to write file", "path", fullPath, "error", err)
		return err
	}

	s.logger.Info("File saved", "key", key, "path", fullPath)

	return nil
}

// SaveStream saves a stream of data to the local file system
func (s *Storage) SaveStream(ctx context.Context, key string, data io.Reader) error {
	// Sanitize the key to prevent directory traversal
	sanitizedKey := s.sanitizeKey(key)
	if sanitizedKey == "" {
		return fmt.Errorf("invalid key")
	}

	fullPath := filepath.Join(s.basePath, sanitizedKey)

	// Create directory if it doesn't exist
	dir := filepath.Dir(fullPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		s.logger.Error("Failed to create directory", "path", dir, "error", err)
		return err
	}

	// Create file
	file, err := os.Create(fullPath)
	if err != nil {
		s.logger.Error("Failed to create file", "path", fullPath, "error", err)
		return err
	}
	defer file.Close()

	// Copy data to file
	if _, err := io.Copy(file, data); err != nil {
		s.logger.Error("Failed to copy data to file", "path", fullPath, "error", err)
		return err
	}

	s.logger.Info("File stream saved", "key", key, "path", fullPath)

	return nil
}

// Get retrieves data from the local file system
func (s *Storage) Get(ctx context.Context, key string) ([]byte, error) {
	// Sanitize the key to prevent directory traversal
	sanitizedKey := s.sanitizeKey(key)
	if sanitizedKey == "" {
		return nil, fmt.Errorf("invalid key")
	}

	fullPath := filepath.Join(s.basePath, sanitizedKey)

	// Read file
	data, err := os.ReadFile(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			s.logger.Debug("File not found", "key", key, "path", fullPath)
			return nil, fmt.Errorf("file not found")
		}
		s.logger.Error("Failed to read file", "path", fullPath, "error", err)
		return nil, err
	}

	s.logger.Debug("File retrieved", "key", key, "path", fullPath)

	return data, nil
}

// GetStream retrieves a stream from the local file system
func (s *Storage) GetStream(ctx context.Context, key string) (io.ReadCloser, error) {
	// Sanitize the key to prevent directory traversal
	sanitizedKey := s.sanitizeKey(key)
	if sanitizedKey == "" {
		return nil, fmt.Errorf("invalid key")
	}

	fullPath := filepath.Join(s.basePath, sanitizedKey)

	// Open file
	file, err := os.Open(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			s.logger.Debug("File not found", "key", key, "path", fullPath)
			return nil, fmt.Errorf("file not found")
		}
		s.logger.Error("Failed to open file", "path", fullPath, "error", err)
		return nil, err
	}

	s.logger.Debug("File stream opened", "key", key, "path", fullPath)

	return file, nil
}

// Delete removes a file from the local file system
func (s *Storage) Delete(ctx context.Context, key string) error {
	// Sanitize the key to prevent directory traversal
	sanitizedKey := s.sanitizeKey(key)
	if sanitizedKey == "" {
		return fmt.Errorf("invalid key")
	}

	fullPath := filepath.Join(s.basePath, sanitizedKey)

	// Remove file
	if err := os.Remove(fullPath); err != nil {
		if os.IsNotExist(err) {
			s.logger.Debug("File already deleted", "key", key, "path", fullPath)
			return nil
		}
		s.logger.Error("Failed to delete file", "path", fullPath, "error", err)
		return err
	}

	s.logger.Info("File deleted", "key", key, "path", fullPath)

	return nil
}

// Exists checks if a file exists in the local file system
func (s *Storage) Exists(ctx context.Context, key string) (bool, error) {
	// Sanitize the key to prevent directory traversal
	sanitizedKey := s.sanitizeKey(key)
	if sanitizedKey == "" {
		return false, fmt.Errorf("invalid key")
	}

	fullPath := filepath.Join(s.basePath, sanitizedKey)

	_, err := os.Stat(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		s.logger.Error("Failed to stat file", "path", fullPath, "error", err)
		return false, err
	}

	return true, nil
}

// List lists files in a directory with optional prefix
func (s *Storage) List(ctx context.Context, prefix string) ([]string, error) {
	var result []string

	// Sanitize the prefix to prevent directory traversal
	sanitizedPrefix := s.sanitizeKey(prefix)
	dirPath := s.basePath

	// If prefix is provided, use it as the directory
	if sanitizedPrefix != "" {
		dirPath = filepath.Join(s.basePath, filepath.Dir(sanitizedPrefix))
	}

	// Walk through the directory
	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		// Get relative path
		relPath, err := filepath.Rel(s.basePath, path)
		if err != nil {
			return err
		}

		// If prefix is provided, filter by prefix
		if sanitizedPrefix != "" && !strings.HasPrefix(relPath, sanitizedPrefix) {
			return nil
		}

		result = append(result, relPath)
		return nil
	})

	if err != nil {
		s.logger.Error("Failed to list files", "error", err)
		return nil, err
	}

	return result, nil
}

// Size returns the size of a file in bytes
func (s *Storage) Size(ctx context.Context, key string) (int64, error) {
	// Sanitize the key to prevent directory traversal
	sanitizedKey := s.sanitizeKey(key)
	if sanitizedKey == "" {
		return 0, fmt.Errorf("invalid key")
	}

	fullPath := filepath.Join(s.basePath, sanitizedKey)

	info, err := os.Stat(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, fmt.Errorf("file not found")
		}
		s.logger.Error("Failed to get file info", "path", fullPath, "error", err)
		return 0, err
	}

	return info.Size(), nil
}

// LastModified returns the last modified time of a file
func (s *Storage) LastModified(ctx context.Context, key string) (*time.Time, error) {
	// Sanitize the key to prevent directory traversal
	sanitizedKey := s.sanitizeKey(key)
	if sanitizedKey == "" {
		return nil, fmt.Errorf("invalid key")
	}

	fullPath := filepath.Join(s.basePath, sanitizedKey)

	info, err := os.Stat(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("file not found")
		}
		s.logger.Error("Failed to get file info", "path", fullPath, "error", err)
		return nil, err
	}

	modTime := info.ModTime()
	return &modTime, nil
}

// Move moves a file from one location to another
func (s *Storage) Move(ctx context.Context, oldKey, newKey string) error {
	// Sanitize both keys to prevent directory traversal
	sanitizedOldKey := s.sanitizeKey(oldKey)
	sanitizedNewKey := s.sanitizeKey(newKey)
	
	if sanitizedOldKey == "" || sanitizedNewKey == "" {
		return fmt.Errorf("invalid key")
	}

	oldPath := filepath.Join(s.basePath, sanitizedOldKey)
	newPath := filepath.Join(s.basePath, sanitizedNewKey)

	// Create directory for new path if needed
	newDir := filepath.Dir(newPath)
	if err := os.MkdirAll(newDir, 0755); err != nil {
		s.logger.Error("Failed to create directory", "path", newDir, "error", err)
		return err
	}

	// Rename file
	if err := os.Rename(oldPath, newPath); err != nil {
		s.logger.Error("Failed to move file", "oldPath", oldPath, "newPath", newPath, "error", err)
		return err
	}

	s.logger.Info("File moved", "oldKey", oldKey, "newKey", newKey)

	return nil
}

// Copy copies a file from one location to another
func (s *Storage) Copy(ctx context.Context, sourceKey, destKey string) error {
	// Sanitize both keys to prevent directory traversal
	sanitizedSourceKey := s.sanitizeKey(sourceKey)
	sanitizedDestKey := s.sanitizeKey(destKey)
	
	if sanitizedSourceKey == "" || sanitizedDestKey == "" {
		return fmt.Errorf("invalid key")
	}

	sourcePath := filepath.Join(s.basePath, sanitizedSourceKey)
	destPath := filepath.Join(s.basePath, sanitizedDestKey)

	// Create directory for destination if needed
	destDir := filepath.Dir(destPath)
	if err := os.MkdirAll(destDir, 0755); err != nil {
		s.logger.Error("Failed to create directory", "path", destDir, "error", err)
		return err
	}

	// Read source file
	sourceData, err := os.ReadFile(sourcePath)
	if err != nil {
		s.logger.Error("Failed to read source file", "path", sourcePath, "error", err)
		return err
	}

	// Write to destination
	if err := os.WriteFile(destPath, sourceData, 0644); err != nil {
		s.logger.Error("Failed to write destination file", "path", destPath, "error", err)
		return err
	}

	s.logger.Info("File copied", "sourceKey", sourceKey, "destKey", destKey)

	return nil
}

// sanitizeKey sanitizes a key to prevent directory traversal
func (s *Storage) sanitizeKey(key string) string {
	// Clean the path to prevent directory traversal
	cleaned := filepath.Clean(key)

	// Remove leading slash if present
	if strings.HasPrefix(cleaned, string(filepath.Separator)) {
		cleaned = cleaned[1:]
	}

	// If the cleaned path is empty or just dots, return empty string
	if cleaned == "" || cleaned == "." || cleaned == ".." {
		return ""
	}

	return cleaned
}