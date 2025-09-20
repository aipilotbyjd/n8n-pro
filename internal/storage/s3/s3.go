package s3

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/url"
	"path"
	"strings"
	"time"

	"n8n-pro/pkg/errors"
	"n8n-pro/pkg/logger"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
)

// Config holds S3 configuration
type Config struct {
	Region          string `json:"region" yaml:"region"`
	Bucket          string `json:"bucket" yaml:"bucket"`
	AccessKeyID     string `json:"access_key_id" yaml:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key" yaml:"secret_access_key"`
	SessionToken    string `json:"session_token" yaml:"session_token"`
	Endpoint        string `json:"endpoint" yaml:"endpoint"`
	UseSSL          bool   `json:"use_ssl" yaml:"use_ssl"`
	PathStyle       bool   `json:"path_style" yaml:"path_style"`
	Prefix          string `json:"prefix" yaml:"prefix"`

	// Advanced settings
	PartSize                 int64         `json:"part_size" yaml:"part_size"`
	Concurrency              int           `json:"concurrency" yaml:"concurrency"`
	LeavePartsOnError        bool          `json:"leave_parts_on_error" yaml:"leave_parts_on_error"`
	ServerSideEncryption     string        `json:"server_side_encryption" yaml:"server_side_encryption"`
	SSEKMSKeyID              string        `json:"sse_kms_key_id" yaml:"sse_kms_key_id"`
	RequestTimeout           time.Duration `json:"request_timeout" yaml:"request_timeout"`
	MaxRetries               int           `json:"max_retries" yaml:"max_retries"`
	DisableSSL               bool          `json:"disable_ssl" yaml:"disable_ssl"`
	DisableComputeChecksums  bool          `json:"disable_compute_checksums" yaml:"disable_compute_checksums"`
	S3ForcePathStyle         bool          `json:"s3_force_path_style" yaml:"s3_force_path_style"`
	S3UseAccelerateEndpoint  bool          `json:"s3_use_accelerate_endpoint" yaml:"s3_use_accelerate_endpoint"`
	S3DisableContentMD5Check bool          `json:"s3_disable_content_md5_check" yaml:"s3_disable_content_md5_check"`
}

// DefaultConfig returns default S3 configuration
func DefaultConfig() *Config {
	return &Config{
		Region:                  "us-east-1",
		UseSSL:                  true,
		PathStyle:               false,
		PartSize:                64 * 1024 * 1024, // 64MB
		Concurrency:             10,
		LeavePartsOnError:       false,
		RequestTimeout:          30 * time.Second,
		MaxRetries:              3,
		DisableSSL:              false,
		DisableComputeChecksums: false,
		S3ForcePathStyle:        false,
	}
}

// FileInfo represents information about a stored file
type FileInfo struct {
	Key          string            `json:"key"`
	Size         int64             `json:"size"`
	ETag         string            `json:"etag"`
	LastModified time.Time         `json:"last_modified"`
	ContentType  string            `json:"content_type"`
	Metadata     map[string]string `json:"metadata"`
	StorageClass string            `json:"storage_class"`
	IsDirectory  bool              `json:"is_directory"`
}

// UploadOptions represents options for file upload
type UploadOptions struct {
	ContentType          string            `json:"content_type"`
	Metadata             map[string]string `json:"metadata"`
	CacheControl         string            `json:"cache_control"`
	ContentDisposition   string            `json:"content_disposition"`
	ContentEncoding      string            `json:"content_encoding"`
	ContentLanguage      string            `json:"content_language"`
	Expires              *time.Time        `json:"expires"`
	ServerSideEncryption string            `json:"server_side_encryption"`
	SSEKMSKeyID          string            `json:"sse_kms_key_id"`
	StorageClass         string            `json:"storage_class"`
	ACL                  string            `json:"acl"`
	Tags                 map[string]string `json:"tags"`
}

// DownloadOptions represents options for file download
type DownloadOptions struct {
	Range     string `json:"range"`
	VersionID string `json:"version_id"`
}

// ListOptions represents options for listing files
type ListOptions struct {
	Prefix     string `json:"prefix"`
	Delimiter  string `json:"delimiter"`
	MaxKeys    int64  `json:"max_keys"`
	StartAfter string `json:"start_after"`
}

// PresignedURLOptions represents options for generating presigned URLs
type PresignedURLOptions struct {
	Expires   time.Duration     `json:"expires"`
	Method    string            `json:"method"`
	Headers   map[string]string `json:"headers"`
	VersionID string            `json:"version_id"`
}

// Client represents an S3 client
type Client struct {
	config     *Config
	s3Client   *s3.S3
	uploader   *s3manager.Uploader
	downloader *s3manager.Downloader
	logger     logger.Logger
}

// New creates a new S3 client
func New(config *Config, log logger.Logger) (*Client, error) {
	if config == nil {
		config = DefaultConfig()
	}

	// Validate required configuration
	if config.Bucket == "" {
		return nil, errors.NewValidationError("S3 bucket name is required")
	}

	// Create AWS session
	awsConfig := &aws.Config{
		Region:                        aws.String(config.Region),
		S3ForcePathStyle:              aws.Bool(config.S3ForcePathStyle || config.PathStyle),
		S3UseAccelerateEndpoint:       aws.Bool(config.S3UseAccelerateEndpoint),
		S3DisableContentMD5Validation: aws.Bool(config.S3DisableContentMD5Check),
		DisableComputeChecksums:       aws.Bool(config.DisableComputeChecksums),
		DisableSSL:                    aws.Bool(config.DisableSSL),
		MaxRetries:                    aws.Int(config.MaxRetries),
	}

	// Set custom endpoint if provided
	if config.Endpoint != "" {
		awsConfig.Endpoint = aws.String(config.Endpoint)
	}

	// Set credentials if provided
	if config.AccessKeyID != "" && config.SecretAccessKey != "" {
		awsConfig.Credentials = credentials.NewStaticCredentials(
			config.AccessKeyID,
			config.SecretAccessKey,
			config.SessionToken,
		)
	}

	// Create session
	sess, err := session.NewSession(awsConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create AWS session: %w", err)
	}

	// Create S3 service client
	s3Client := s3.New(sess)

	// Create uploader and downloader
	uploader := s3manager.NewUploaderWithClient(s3Client, func(u *s3manager.Uploader) {
		u.PartSize = config.PartSize
		u.Concurrency = config.Concurrency
		u.LeavePartsOnError = config.LeavePartsOnError
	})

	downloader := s3manager.NewDownloaderWithClient(s3Client, func(d *s3manager.Downloader) {
		d.PartSize = config.PartSize
		d.Concurrency = config.Concurrency
	})

	client := &Client{
		config:     config,
		s3Client:   s3Client,
		uploader:   uploader,
		downloader: downloader,
		logger:     log,
	}

	log.Info("S3 client created",
		"bucket", config.Bucket,
		"region", config.Region,
		"endpoint", config.Endpoint,
	)

	return client, nil
}

// Upload uploads a file to S3
func (c *Client) Upload(ctx context.Context, key string, data io.Reader, options *UploadOptions) (*FileInfo, error) {
	if options == nil {
		options = &UploadOptions{}
	}

	// Add prefix to key if configured
	key = c.buildKey(key)

	c.logger.Info("Uploading file to S3", "key", key, "bucket", c.config.Bucket)

	// Prepare upload input
	input := &s3manager.UploadInput{
		Bucket: aws.String(c.config.Bucket),
		Key:    aws.String(key),
		Body:   data,
	}

	// Set options
	if options.ContentType != "" {
		input.ContentType = aws.String(options.ContentType)
	}
	if options.CacheControl != "" {
		input.CacheControl = aws.String(options.CacheControl)
	}
	if options.ContentDisposition != "" {
		input.ContentDisposition = aws.String(options.ContentDisposition)
	}
	if options.ContentEncoding != "" {
		input.ContentEncoding = aws.String(options.ContentEncoding)
	}
	if options.ContentLanguage != "" {
		input.ContentLanguage = aws.String(options.ContentLanguage)
	}
	if options.Expires != nil {
		input.Expires = options.Expires
	}
	if options.ACL != "" {
		input.ACL = aws.String(options.ACL)
	}
	if options.StorageClass != "" {
		input.StorageClass = aws.String(options.StorageClass)
	}

	// Set server-side encryption
	if options.ServerSideEncryption != "" || c.config.ServerSideEncryption != "" {
		sse := options.ServerSideEncryption
		if sse == "" {
			sse = c.config.ServerSideEncryption
		}
		input.ServerSideEncryption = aws.String(sse)

		// Set KMS key ID if provided
		kmsKeyID := options.SSEKMSKeyID
		if kmsKeyID == "" {
			kmsKeyID = c.config.SSEKMSKeyID
		}
		if kmsKeyID != "" {
			input.SSEKMSKeyId = aws.String(kmsKeyID)
		}
	}

	// Set metadata
	if len(options.Metadata) > 0 {
		input.Metadata = aws.StringMap(options.Metadata)
	}

	// Set tags
	if len(options.Tags) > 0 {
		var tagSet []*s3.Tag
		for k, v := range options.Tags {
			tagSet = append(tagSet, &s3.Tag{
				Key:   aws.String(k),
				Value: aws.String(v),
			})
		}
		input.Tagging = aws.String(c.buildTagString(options.Tags))
	}

	// Perform upload
	result, err := c.uploader.UploadWithContext(ctx, input)
	if err != nil {
		c.logger.Error("Failed to upload file to S3", "error", err, "key", key)
		return nil, c.handleS3Error(err)
	}

	c.logger.Info("File uploaded successfully", "key", key, "location", result.Location)

	// Get file info
	info, err := c.HeadObject(ctx, key)
	if err != nil {
		// If we can't get file info, create basic info from upload result
		info = &FileInfo{
			Key:  key,
			ETag: aws.StringValue(result.VersionID), // This might be empty
		}
	}

	return info, nil
}

// UploadFromBytes uploads data from byte slice
func (c *Client) UploadFromBytes(ctx context.Context, key string, data []byte, options *UploadOptions) (*FileInfo, error) {
	return c.Upload(ctx, key, bytes.NewReader(data), options)
}

// Download downloads a file from S3
func (c *Client) Download(ctx context.Context, key string, writer io.WriterAt, options *DownloadOptions) error {
	if options == nil {
		options = &DownloadOptions{}
	}

	key = c.buildKey(key)

	c.logger.Info("Downloading file from S3", "key", key, "bucket", c.config.Bucket)

	input := &s3.GetObjectInput{
		Bucket: aws.String(c.config.Bucket),
		Key:    aws.String(key),
	}

	if options.Range != "" {
		input.Range = aws.String(options.Range)
	}
	if options.VersionID != "" {
		input.VersionId = aws.String(options.VersionID)
	}

	_, err := c.downloader.DownloadWithContext(ctx, writer, input)
	if err != nil {
		c.logger.Error("Failed to download file from S3", "error", err, "key", key)
		return c.handleS3Error(err)
	}

	c.logger.Info("File downloaded successfully", "key", key)
	return nil
}

// DownloadToBytes downloads a file to a byte slice
func (c *Client) DownloadToBytes(ctx context.Context, key string, options *DownloadOptions) ([]byte, error) {
	buf := &aws.WriteAtBuffer{}
	err := c.Download(ctx, key, buf, options)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Delete deletes a file from S3
func (c *Client) Delete(ctx context.Context, key string) error {
	key = c.buildKey(key)

	c.logger.Info("Deleting file from S3", "key", key, "bucket", c.config.Bucket)

	input := &s3.DeleteObjectInput{
		Bucket: aws.String(c.config.Bucket),
		Key:    aws.String(key),
	}

	_, err := c.s3Client.DeleteObjectWithContext(ctx, input)
	if err != nil {
		c.logger.Error("Failed to delete file from S3", "error", err, "key", key)
		return c.handleS3Error(err)
	}

	c.logger.Info("File deleted successfully", "key", key)
	return nil
}

// DeleteMany deletes multiple files from S3
func (c *Client) DeleteMany(ctx context.Context, keys []string) error {
	if len(keys) == 0 {
		return nil
	}

	c.logger.Info("Deleting multiple files from S3", "count", len(keys), "bucket", c.config.Bucket)

	// Build delete objects
	var objects []*s3.ObjectIdentifier
	for _, key := range keys {
		objects = append(objects, &s3.ObjectIdentifier{
			Key: aws.String(c.buildKey(key)),
		})
	}

	input := &s3.DeleteObjectsInput{
		Bucket: aws.String(c.config.Bucket),
		Delete: &s3.Delete{
			Objects: objects,
			Quiet:   aws.Bool(true),
		},
	}

	result, err := c.s3Client.DeleteObjectsWithContext(ctx, input)
	if err != nil {
		c.logger.Error("Failed to delete files from S3", "error", err)
		return c.handleS3Error(err)
	}

	if len(result.Errors) > 0 {
		c.logger.Error("Some files failed to delete", "errors", len(result.Errors))
		return fmt.Errorf("failed to delete %d files", len(result.Errors))
	}

	c.logger.Info("Files deleted successfully", "count", len(keys))
	return nil
}

// Exists checks if a file exists in S3
func (c *Client) Exists(ctx context.Context, key string) (bool, error) {
	key = c.buildKey(key)

	input := &s3.HeadObjectInput{
		Bucket: aws.String(c.config.Bucket),
		Key:    aws.String(key),
	}

	_, err := c.s3Client.HeadObjectWithContext(ctx, input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			if aerr.Code() == s3.ErrCodeNoSuchKey || aerr.Code() == "NotFound" {
				return false, nil
			}
		}
		return false, c.handleS3Error(err)
	}

	return true, nil
}

// HeadObject gets metadata for an object
func (c *Client) HeadObject(ctx context.Context, key string) (*FileInfo, error) {
	key = c.buildKey(key)

	input := &s3.HeadObjectInput{
		Bucket: aws.String(c.config.Bucket),
		Key:    aws.String(key),
	}

	result, err := c.s3Client.HeadObjectWithContext(ctx, input)
	if err != nil {
		return nil, c.handleS3Error(err)
	}

	// Convert metadata
	metadata := make(map[string]string)
	for k, v := range result.Metadata {
		if v != nil {
			metadata[k] = *v
		}
	}

	info := &FileInfo{
		Key:          key,
		Size:         aws.Int64Value(result.ContentLength),
		ETag:         aws.StringValue(result.ETag),
		LastModified: aws.TimeValue(result.LastModified),
		ContentType:  aws.StringValue(result.ContentType),
		Metadata:     metadata,
		StorageClass: aws.StringValue(result.StorageClass),
		IsDirectory:  false,
	}

	return info, nil
}

// List lists files in S3
func (c *Client) List(ctx context.Context, options *ListOptions) ([]*FileInfo, error) {
	if options == nil {
		options = &ListOptions{}
	}

	prefix := c.buildKey(options.Prefix)

	input := &s3.ListObjectsV2Input{
		Bucket:  aws.String(c.config.Bucket),
		Prefix:  aws.String(prefix),
		MaxKeys: aws.Int64(options.MaxKeys),
	}

	if options.Delimiter != "" {
		input.Delimiter = aws.String(options.Delimiter)
	}
	if options.StartAfter != "" {
		input.StartAfter = aws.String(c.buildKey(options.StartAfter))
	}

	var files []*FileInfo

	err := c.s3Client.ListObjectsV2PagesWithContext(ctx, input, func(page *s3.ListObjectsV2Output, lastPage bool) bool {
		for _, obj := range page.Contents {
			info := &FileInfo{
				Key:          c.stripPrefix(aws.StringValue(obj.Key)),
				Size:         aws.Int64Value(obj.Size),
				ETag:         aws.StringValue(obj.ETag),
				LastModified: aws.TimeValue(obj.LastModified),
				StorageClass: aws.StringValue(obj.StorageClass),
				IsDirectory:  false,
			}
			files = append(files, info)
		}

		// Handle common prefixes (directories)
		for _, prefix := range page.CommonPrefixes {
			info := &FileInfo{
				Key:         c.stripPrefix(aws.StringValue(prefix.Prefix)),
				IsDirectory: true,
			}
			files = append(files, info)
		}

		return !lastPage
	})

	if err != nil {
		return nil, c.handleS3Error(err)
	}

	return files, nil
}

// Copy copies an object within S3
func (c *Client) Copy(ctx context.Context, srcKey, destKey string, options *UploadOptions) error {
	srcKey = c.buildKey(srcKey)
	destKey = c.buildKey(destKey)

	c.logger.Info("Copying file in S3", "src", srcKey, "dest", destKey)

	copySource := fmt.Sprintf("%s/%s", c.config.Bucket, url.PathEscape(srcKey))

	input := &s3.CopyObjectInput{
		Bucket:     aws.String(c.config.Bucket),
		CopySource: aws.String(copySource),
		Key:        aws.String(destKey),
	}

	// Apply options if provided
	if options != nil {
		if options.ContentType != "" {
			input.ContentType = aws.String(options.ContentType)
		}
		if options.CacheControl != "" {
			input.CacheControl = aws.String(options.CacheControl)
		}
		if options.ContentDisposition != "" {
			input.ContentDisposition = aws.String(options.ContentDisposition)
		}
		if options.ACL != "" {
			input.ACL = aws.String(options.ACL)
		}
		if options.StorageClass != "" {
			input.StorageClass = aws.String(options.StorageClass)
		}
		if len(options.Metadata) > 0 {
			input.Metadata = aws.StringMap(options.Metadata)
			input.MetadataDirective = aws.String(s3.MetadataDirectiveReplace)
		}
	}

	_, err := c.s3Client.CopyObjectWithContext(ctx, input)
	if err != nil {
		c.logger.Error("Failed to copy file in S3", "error", err, "src", srcKey, "dest", destKey)
		return c.handleS3Error(err)
	}

	c.logger.Info("File copied successfully", "src", srcKey, "dest", destKey)
	return nil
}

// GeneratePresignedURL generates a presigned URL for an object
func (c *Client) GeneratePresignedURL(ctx context.Context, key string, options *PresignedURLOptions) (string, error) {
	if options == nil {
		options = &PresignedURLOptions{
			Expires: 15 * time.Minute,
			Method:  "GET",
		}
	}

	key = c.buildKey(key)

	var req *s3.GetObjectInput
	var operation string

	switch strings.ToUpper(options.Method) {
	case "GET":
		req = &s3.GetObjectInput{
			Bucket: aws.String(c.config.Bucket),
			Key:    aws.String(key),
		}
		if options.VersionID != "" {
			req.VersionId = aws.String(options.VersionID)
		}
		operation = "GetObject"
	case "PUT":
		putReq := &s3.PutObjectInput{
			Bucket: aws.String(c.config.Bucket),
			Key:    aws.String(key),
		}
		req = putReq
		operation = "PutObject"
	case "DELETE":
		deleteReq := &s3.DeleteObjectInput{
			Bucket: aws.String(c.config.Bucket),
			Key:    aws.String(key),
		}
		req = deleteReq
		operation = "DeleteObject"
	default:
		return "", errors.NewValidationError(fmt.Sprintf("unsupported method: %s", options.Method))
	}

	presignReq, _ := c.s3Client.GetObjectRequest(req.(*s3.GetObjectInput))
	url, err := presignReq.Presign(options.Expires)
	if err != nil {
		return "", fmt.Errorf("failed to generate presigned URL: %w", err)
	}

	return url, nil
}

// Helper methods

// buildKey adds the configured prefix to a key
func (c *Client) buildKey(key string) string {
	if c.config.Prefix == "" {
		return key
	}
	return path.Join(c.config.Prefix, key)
}

// stripPrefix removes the configured prefix from a key
func (c *Client) stripPrefix(key string) string {
	if c.config.Prefix == "" {
		return key
	}
	return strings.TrimPrefix(key, c.config.Prefix+"/")
}

// buildTagString builds a tag string for S3 operations
func (c *Client) buildTagString(tags map[string]string) string {
	var parts []string
	for k, v := range tags {
		parts = append(parts, fmt.Sprintf("%s=%s", url.QueryEscape(k), url.QueryEscape(v)))
	}
	return strings.Join(parts, "&")
}

// handleS3Error converts S3 errors to application errors
func (c *Client) handleS3Error(err error) error {
	if aerr, ok := err.(awserr.Error); ok {
		switch aerr.Code() {
		case s3.ErrCodeNoSuchBucket:
			return errors.NewNotFoundError("S3 bucket not found")
		case s3.ErrCodeNoSuchKey:
			return errors.NewNotFoundError("S3 object not found")
		case "AccessDenied":
			return errors.NewForbiddenError("S3 access denied")
		case "InvalidAccessKeyId":
			return errors.NewUnauthorizedError("Invalid S3 access key")
		case "SignatureDoesNotMatch":
			return errors.NewUnauthorizedError("Invalid S3 secret key")
		case "RequestTimeout":
			return errors.NewTimeoutError("S3 request timeout")
		default:
			return errors.NewExecutionError(fmt.Sprintf("S3 error: %s - %s", aerr.Code(), aerr.Message()))
		}
	}

	return errors.NewExecutionError(fmt.Sprintf("S3 operation failed: %v", err))
}

// GetBucketLocation gets the location of the bucket
func (c *Client) GetBucketLocation(ctx context.Context) (string, error) {
	input := &s3.GetBucketLocationInput{
		Bucket: aws.String(c.config.Bucket),
	}

	result, err := c.s3Client.GetBucketLocationWithContext(ctx, input)
	if err != nil {
		return "", c.handleS3Error(err)
	}

	location := aws.StringValue(result.LocationConstraint)
	if location == "" {
		location = "us-east-1" // Default for empty location constraint
	}

	return location, nil
}

// CreateBucket creates a bucket
func (c *Client) CreateBucket(ctx context.Context) error {
	input := &s3.CreateBucketInput{
		Bucket: aws.String(c.config.Bucket),
	}

	// Set location constraint for regions other than us-east-1
	if c.config.Region != "" && c.config.Region != "us-east-1" {
		input.CreateBucketConfiguration = &s3.CreateBucketConfiguration{
			LocationConstraint: aws.String(c.config.Region),
		}
	}

	_, err := c.s3Client.CreateBucketWithContext(ctx, input)
	if err != nil {
		return c.handleS3Error(err)
	}

	c.logger.Info("S3 bucket created successfully", "bucket", c.config.Bucket)
	return nil
}

// DeleteBucket deletes a bucket (must be empty)
func (c *Client) DeleteBucket(ctx context.Context) error {
	input := &s3.DeleteBucketInput{
		Bucket: aws.String(c.config.Bucket),
	}

	_, err := c.s3Client.DeleteBucketWithContext(ctx, input)
	if err != nil {
		return c.handleS3Error(err)
	}

	c.logger.Info("S3 bucket deleted successfully", "bucket", c.config.Bucket)
	return nil
}

// GetBucketPolicy gets the bucket policy
func (c *Client) GetBucketPolicy(ctx context.Context) (string, error) {
	input := &s3.GetBucketPolicyInput{
		Bucket: aws.String(c.config.Bucket),
	}

	result, err := c.s3Client.GetBucketPolicyWithContext(ctx, input)
	if err != nil {
		return "", c.handleS3Error(err)
	}

	return aws.StringValue(result.Policy), nil
}

// SetBucketPolicy sets the bucket policy
func (c *Client) SetBucketPolicy(ctx context.Context, policy string) error {
	input := &s3.PutBucketPolicyInput{
		Bucket: aws.String(c.config.Bucket),
		Policy: aws.String(policy),
	}

	_, err := c.s3Client.PutBucketPolicyWithContext(ctx, input)
	if err != nil {
		return c.handleS3Error(err)
	}

	c.logger.Info("S3 bucket policy set successfully", "bucket", c.config.Bucket)
	return nil
}

// Close closes the S3 client (cleanup)
func (c *Client) Close() error {
	// No explicit cleanup needed for AWS SDK
	c.logger.Info("S3 client closed", "bucket", c.config.Bucket)
	return nil
}
