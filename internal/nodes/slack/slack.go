package slack

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"n8n-pro/internal/nodes"
	"n8n-pro/pkg/errors"
	"n8n-pro/pkg/logger"
)

// SlackExecutor implements Slack operations for workflow nodes
type SlackExecutor struct {
	logger     logger.Logger
	httpClient *http.Client
}

// SlackConfig represents Slack operation configuration
type SlackConfig struct {
	Operation   string                 `json:"operation"`   // send_message, get_channel, list_channels, etc.
	Channel     string                 `json:"channel"`     // Channel ID or name
	Message     string                 `json:"message"`     // Message text
	Username    string                 `json:"username"`    // Bot username
	IconEmoji   string                 `json:"icon_emoji"`  // Bot icon emoji
	IconURL     string                 `json:"icon_url"`    // Bot icon URL
	Attachments []SlackAttachment      `json:"attachments"` // Message attachments
	Blocks      []SlackBlock           `json:"blocks"`      // Message blocks
	ThreadTS    string                 `json:"thread_ts"`   // Thread timestamp for replies
	Auth        AuthConfig             `json:"auth"`        // Authentication config
	Options     map[string]interface{} `json:"options"`     // Additional options
}

// AuthConfig represents Slack authentication configuration
type AuthConfig struct {
	Type        string `json:"type"`         // bot_token, oauth2, webhook
	BotToken    string `json:"bot_token"`    // Slack Bot User OAuth Token
	WebhookURL  string `json:"webhook_url"`  // Slack Webhook URL
	AccessToken string `json:"access_token"` // OAuth2 access token
}

// SlackAttachment represents a Slack message attachment
type SlackAttachment struct {
	Color      string                   `json:"color,omitempty"`
	Pretext    string                   `json:"pretext,omitempty"`
	AuthorName string                   `json:"author_name,omitempty"`
	AuthorLink string                   `json:"author_link,omitempty"`
	AuthorIcon string                   `json:"author_icon,omitempty"`
	Title      string                   `json:"title,omitempty"`
	TitleLink  string                   `json:"title_link,omitempty"`
	Text       string                   `json:"text,omitempty"`
	Fields     []SlackAttachmentField   `json:"fields,omitempty"`
	ImageURL   string                   `json:"image_url,omitempty"`
	ThumbURL   string                   `json:"thumb_url,omitempty"`
	Footer     string                   `json:"footer,omitempty"`
	FooterIcon string                   `json:"footer_icon,omitempty"`
	Timestamp  int64                    `json:"ts,omitempty"`
	Actions    []map[string]interface{} `json:"actions,omitempty"`
}

// SlackAttachmentField represents a field in a Slack attachment
type SlackAttachmentField struct {
	Title string `json:"title"`
	Value string `json:"value"`
	Short bool   `json:"short"`
}

// SlackBlock represents a Slack Block Kit block
type SlackBlock struct {
	Type      string                 `json:"type"`
	Text      *SlackText             `json:"text,omitempty"`
	Elements  []SlackBlockElement    `json:"elements,omitempty"`
	Fields    []SlackText            `json:"fields,omitempty"`
	Accessory map[string]interface{} `json:"accessory,omitempty"`
}

// SlackText represents Slack text object
type SlackText struct {
	Type string `json:"type"` // plain_text or mrkdwn
	Text string `json:"text"`
}

// SlackBlockElement represents a block element
type SlackBlockElement struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
	URL  string `json:"url,omitempty"`
}

// SlackResponse represents the response from Slack operations
type SlackResponse struct {
	Operation     string                 `json:"operation"`
	Success       bool                   `json:"success"`
	Channel       string                 `json:"channel,omitempty"`
	Message       string                 `json:"message,omitempty"`
	MessageTS     string                 `json:"message_ts,omitempty"`
	ThreadTS      string                 `json:"thread_ts,omitempty"`
	Data          map[string]interface{} `json:"data,omitempty"`
	ExecutionTime int64                  `json:"execution_time"` // milliseconds
}

// SlackAPIResponse represents a generic Slack API response
type SlackAPIResponse struct {
	OK       bool                   `json:"ok"`
	Error    string                 `json:"error,omitempty"`
	Message  map[string]interface{} `json:"message,omitempty"`
	Channel  string                 `json:"channel,omitempty"`
	TS       string                 `json:"ts,omitempty"`
	Channels []SlackChannel         `json:"channels,omitempty"`
}

// SlackChannel represents a Slack channel
type SlackChannel struct {
	ID                 string `json:"id"`
	Name               string `json:"name"`
	IsChannel          bool   `json:"is_channel"`
	IsGroup            bool   `json:"is_group"`
	IsIM               bool   `json:"is_im"`
	Created            int64  `json:"created"`
	IsArchived         bool   `json:"is_archived"`
	IsGeneral          bool   `json:"is_general"`
	Unlinked           int    `json:"unlinked"`
	NameNormalized     string `json:"name_normalized"`
	IsShared           bool   `json:"is_shared"`
	ParentConversation string `json:"parent_conversation"`
	Creator            string `json:"creator"`
	IsExtShared        bool   `json:"is_ext_shared"`
	IsOrgShared        bool   `json:"is_org_shared"`
	IsPendingExtShared bool   `json:"is_pending_ext_shared"`
	IsMember           bool   `json:"is_member"`
	IsPrivate          bool   `json:"is_private"`
	IsMpim             bool   `json:"is_mpim"`
}

// New creates a new Slack executor
func New(log logger.Logger) *SlackExecutor {
	return &SlackExecutor{
		logger: log,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Execute performs the Slack operation
func (e *SlackExecutor) Execute(ctx context.Context, parameters map[string]interface{}, inputData interface{}) (interface{}, error) {
	startTime := time.Now()

	// Parse configuration
	config, err := e.parseConfig(parameters)
	if err != nil {
		return nil, errors.NewValidationError(fmt.Sprintf("Invalid Slack configuration: %v", err))
	}

	// Validate configuration
	if err := e.validateConfig(config); err != nil {
		return nil, err
	}

	e.logger.Info("Executing Slack operation",
		"operation", config.Operation,
		"channel", config.Channel,
	)

	// Execute operation
	response, err := e.executeOperation(ctx, config, inputData)
	if err != nil {
		return nil, errors.NewExecutionError(fmt.Sprintf("Slack operation failed: %v", err))
	}

	response.ExecutionTime = time.Since(startTime).Milliseconds()

	e.logger.Info("Slack operation completed",
		"operation", config.Operation,
		"success", response.Success,
		"execution_time_ms", response.ExecutionTime,
	)

	return response, nil
}

// Validate validates the Slack node parameters
func (e *SlackExecutor) Validate(parameters map[string]interface{}) error {
	config, err := e.parseConfig(parameters)
	if err != nil {
		return errors.NewValidationError(fmt.Sprintf("Invalid configuration: %v", err))
	}

	return e.validateConfig(config)
}

// GetDefinition returns the node definition
func (e *SlackExecutor) GetDefinition() *nodes.NodeDefinition {
	return &nodes.NodeDefinition{
		Name:        "n8n-nodes-base.slack",
		DisplayName: "Slack",
		Description: "Send messages and interact with Slack",
		Version:     "2.0.0",
		Type:        nodes.NodeTypeIntegration,
		Category:    nodes.CategoryCommunication,
		Status:      nodes.NodeStatusStable,
		Icon:        "file:slack.svg",
		Color:       "#4A154B",
		Subtitle:    "={{$parameter[\"operation\"]}} {{$parameter[\"channel\"]}}",
		Group:       []string{"output"},
		Tags:        []string{"slack", "messaging", "communication", "chat", "notifications"},
		Parameters: []nodes.Parameter{
			{
				Name:        "operation",
				DisplayName: "Operation",
				Type:        nodes.ParameterTypeOptions,
				Description: "Operation to perform",
				Required:    true,
				Default:     "send_message",
				Options: []nodes.Option{
					{Value: "send_message", Label: "Send Message", Description: "Send a message to a channel"},
					{Value: "get_channel", Label: "Get Channel", Description: "Get channel information"},
					{Value: "list_channels", Label: "List Channels", Description: "List all channels"},
					{Value: "upload_file", Label: "Upload File", Description: "Upload a file to Slack"},
				},
			},
			{
				Name:        "auth_type",
				DisplayName: "Authentication",
				Type:        nodes.ParameterTypeOptions,
				Description: "Authentication method",
				Required:    true,
				Default:     "bot_token",
				Options: []nodes.Option{
					{Value: "bot_token", Label: "Bot Token", Description: "Use Slack Bot User OAuth Token"},
					{Value: "webhook", Label: "Webhook", Description: "Use Slack Incoming Webhook"},
					{Value: "oauth2", Label: "OAuth2", Description: "Use OAuth2 authentication"},
				},
			},
			{
				Name:        "bot_token",
				DisplayName: "Bot Token",
				Type:        nodes.ParameterTypeString,
				Description: "Slack Bot User OAuth Token",
				ShowIf:      "auth_type=bot_token",
				Placeholder: "xoxb-your-bot-token-here",
			},
			{
				Name:        "webhook_url",
				DisplayName: "Webhook URL",
				Type:        nodes.ParameterTypeString,
				Description: "Slack Incoming Webhook URL",
				ShowIf:      "auth_type=webhook",
				Placeholder: "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX",
			},
			{
				Name:        "channel",
				DisplayName: "Channel",
				Type:        nodes.ParameterTypeString,
				Description: "Channel name or ID",
				Required:    true,
				ShowIf:      "operation!=list_channels",
				Placeholder: "#general or C1234567890",
			},
			{
				Name:        "message",
				DisplayName: "Message",
				Type:        nodes.ParameterTypeString,
				Description: "Message text to send",
				ShowIf:      "operation=send_message",
				Placeholder: "Hello from n8n!",
			},
			{
				Name:        "username",
				DisplayName: "Username",
				Type:        nodes.ParameterTypeString,
				Description: "Bot username (for webhooks)",
				ShowIf:      "auth_type=webhook",
				Placeholder: "n8n-bot",
			},
			{
				Name:        "icon_emoji",
				DisplayName: "Icon Emoji",
				Type:        nodes.ParameterTypeString,
				Description: "Bot icon emoji",
				ShowIf:      "auth_type=webhook",
				Placeholder: ":robot_face:",
			},
			{
				Name:        "icon_url",
				DisplayName: "Icon URL",
				Type:        nodes.ParameterTypeString,
				Description: "Bot icon URL",
				ShowIf:      "auth_type=webhook",
			},
			{
				Name:        "thread_ts",
				DisplayName: "Thread Timestamp",
				Type:        nodes.ParameterTypeString,
				Description: "Timestamp of parent message to reply in thread",
				ShowIf:      "operation=send_message",
			},
			{
				Name:        "attachments",
				DisplayName: "Attachments",
				Type:        nodes.ParameterTypeArray,
				Description: "Message attachments (legacy format)",
				ShowIf:      "operation=send_message",
			},
			{
				Name:        "blocks",
				DisplayName: "Blocks",
				Type:        nodes.ParameterTypeArray,
				Description: "Block Kit blocks",
				ShowIf:      "operation=send_message",
			},
		},
		Inputs: []nodes.NodeInput{
			{Name: "main", DisplayName: "Main", Type: "main", Required: false, MaxConnections: 1},
		},
		Outputs: []nodes.NodeOutput{
			{Name: "main", DisplayName: "Main", Type: "main", Description: "Slack operation results"},
		},
		Credentials:      []string{"slackOAuth2", "slackWebhook", "slackBotToken"},
		RetryOnFail:      2,
		ContinueOnFail:   false,
		AlwaysOutputData: false,
		MaxExecutionTime: 1 * time.Minute,
		DocumentationURL: "https://docs.n8n.io/nodes/n8n-nodes-base.slack/",
		Examples: []nodes.NodeExample{
			{
				Name:        "Send simple message",
				Description: "Send a simple message to a Slack channel",
				Parameters: map[string]interface{}{
					"operation": "send_message",
					"channel":   "#general",
					"message":   "Hello from n8n!",
				},
			},
			{
				Name:        "Send message with attachment",
				Description: "Send a message with a rich attachment",
				Parameters: map[string]interface{}{
					"operation": "send_message",
					"channel":   "#general",
					"message":   "Workflow completed!",
					"attachments": []map[string]interface{}{
						{
							"color": "good",
							"title": "Workflow Status",
							"text":  "The workflow executed successfully.",
							"fields": []map[string]interface{}{
								{"title": "Duration", "value": "2.3 seconds", "short": true},
								{"title": "Items", "value": "15", "short": true},
							},
						},
					},
				},
			},
		},
		Dependencies: []string{},
		Author:       "n8n Team",
		License:      "MIT",
	}
}

// parseConfig parses parameters into SlackConfig
func (e *SlackExecutor) parseConfig(parameters map[string]interface{}) (*SlackConfig, error) {
	config := &SlackConfig{
		Operation: "send_message",
		Auth:      AuthConfig{Type: "bot_token"},
		Options:   make(map[string]interface{}),
	}

	if operation, ok := parameters["operation"].(string); ok {
		config.Operation = operation
	}

	if channel, ok := parameters["channel"].(string); ok {
		config.Channel = channel
	}

	if message, ok := parameters["message"].(string); ok {
		config.Message = message
	}

	if username, ok := parameters["username"].(string); ok {
		config.Username = username
	}

	if iconEmoji, ok := parameters["icon_emoji"].(string); ok {
		config.IconEmoji = iconEmoji
	}

	if iconURL, ok := parameters["icon_url"].(string); ok {
		config.IconURL = iconURL
	}

	if threadTS, ok := parameters["thread_ts"].(string); ok {
		config.ThreadTS = threadTS
	}

	// Parse authentication
	if authType, ok := parameters["auth_type"].(string); ok {
		config.Auth.Type = authType
	}

	if botToken, ok := parameters["bot_token"].(string); ok {
		config.Auth.BotToken = botToken
	}

	if webhookURL, ok := parameters["webhook_url"].(string); ok {
		config.Auth.WebhookURL = webhookURL
	}

	if accessToken, ok := parameters["access_token"].(string); ok {
		config.Auth.AccessToken = accessToken
	}

	// Parse attachments
	if attachments, ok := parameters["attachments"].([]interface{}); ok {
		for _, att := range attachments {
			if attMap, ok := att.(map[string]interface{}); ok {
				attachment := SlackAttachment{}
				// Parse attachment fields - simplified for brevity
				if color, ok := attMap["color"].(string); ok {
					attachment.Color = color
				}
				if title, ok := attMap["title"].(string); ok {
					attachment.Title = title
				}
				if text, ok := attMap["text"].(string); ok {
					attachment.Text = text
				}
				config.Attachments = append(config.Attachments, attachment)
			}
		}
	}

	return config, nil
}

// validateConfig validates the Slack configuration
func (e *SlackExecutor) validateConfig(config *SlackConfig) error {
	validOperations := map[string]bool{
		"send_message":  true,
		"get_channel":   true,
		"list_channels": true,
		"upload_file":   true,
	}

	if !validOperations[config.Operation] {
		return errors.NewValidationError(fmt.Sprintf("Invalid operation: %s", config.Operation))
	}

	if config.Operation != "list_channels" && config.Channel == "" {
		return errors.NewValidationError("Channel is required for this operation")
	}

	// Validate authentication
	switch config.Auth.Type {
	case "bot_token":
		if config.Auth.BotToken == "" {
			return errors.NewValidationError("Bot token is required")
		}
	case "webhook":
		if config.Auth.WebhookURL == "" {
			return errors.NewValidationError("Webhook URL is required")
		}
	case "oauth2":
		if config.Auth.AccessToken == "" {
			return errors.NewValidationError("Access token is required for OAuth2")
		}
	default:
		return errors.NewValidationError("Invalid authentication type")
	}

	return nil
}

// executeOperation executes the Slack operation
func (e *SlackExecutor) executeOperation(ctx context.Context, config *SlackConfig, inputData interface{}) (*SlackResponse, error) {
	switch config.Operation {
	case "send_message":
		return e.executeSendMessage(ctx, config)
	case "get_channel":
		return e.executeGetChannel(ctx, config)
	case "list_channels":
		return e.executeListChannels(ctx, config)
	case "upload_file":
		return e.executeUploadFile(ctx, config)
	default:
		return nil, fmt.Errorf("unsupported operation: %s", config.Operation)
	}
}

// executeSendMessage sends a message to Slack
func (e *SlackExecutor) executeSendMessage(ctx context.Context, config *SlackConfig) (*SlackResponse, error) {
	if config.Auth.Type == "webhook" {
		return e.sendWebhookMessage(ctx, config)
	}
	return e.sendAPIMessage(ctx, config)
}

// sendWebhookMessage sends a message via webhook
func (e *SlackExecutor) sendWebhookMessage(ctx context.Context, config *SlackConfig) (*SlackResponse, error) {
	payload := map[string]interface{}{
		"text":    config.Message,
		"channel": config.Channel,
	}

	if config.Username != "" {
		payload["username"] = config.Username
	}
	if config.IconEmoji != "" {
		payload["icon_emoji"] = config.IconEmoji
	}
	if config.IconURL != "" {
		payload["icon_url"] = config.IconURL
	}
	if len(config.Attachments) > 0 {
		payload["attachments"] = config.Attachments
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal webhook payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", config.Auth.WebhookURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create webhook request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("webhook request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("webhook request failed with status: %d", resp.StatusCode)
	}

	return &SlackResponse{
		Operation: "send_message",
		Success:   true,
		Channel:   config.Channel,
		Message:   config.Message,
	}, nil
}

// sendAPIMessage sends a message via Slack API
func (e *SlackExecutor) sendAPIMessage(ctx context.Context, config *SlackConfig) (*SlackResponse, error) {
	payload := map[string]interface{}{
		"channel": config.Channel,
		"text":    config.Message,
	}

	if config.ThreadTS != "" {
		payload["thread_ts"] = config.ThreadTS
	}
	if len(config.Attachments) > 0 {
		payload["attachments"] = config.Attachments
	}
	if len(config.Blocks) > 0 {
		payload["blocks"] = config.Blocks
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal API payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", "https://slack.com/api/chat.postMessage", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create API request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+config.Auth.BotToken)

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("API request failed: %w", err)
	}
	defer resp.Body.Close()

	var slackResp SlackAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&slackResp); err != nil {
		return nil, fmt.Errorf("failed to decode API response: %w", err)
	}

	if !slackResp.OK {
		return nil, fmt.Errorf("Slack API error: %s", slackResp.Error)
	}

	return &SlackResponse{
		Operation: "send_message",
		Success:   true,
		Channel:   config.Channel,
		Message:   config.Message,
		MessageTS: slackResp.TS,
		ThreadTS:  config.ThreadTS,
	}, nil
}

// executeGetChannel gets channel information
func (e *SlackExecutor) executeGetChannel(ctx context.Context, config *SlackConfig) (*SlackResponse, error) {
	// In a real implementation, this would call Slack API
	// For now, return mock data
	mockChannel := SlackChannel{
		ID:             "C1234567890",
		Name:           strings.TrimPrefix(config.Channel, "#"),
		IsChannel:      true,
		Created:        time.Now().Unix(),
		IsArchived:     false,
		IsGeneral:      false,
		NameNormalized: strings.TrimPrefix(config.Channel, "#"),
		IsMember:       true,
		IsPrivate:      false,
	}

	return &SlackResponse{
		Operation: "get_channel",
		Success:   true,
		Channel:   config.Channel,
		Data:      map[string]interface{}{"channel": mockChannel},
	}, nil
}

// executeListChannels lists all channels
func (e *SlackExecutor) executeListChannels(ctx context.Context, config *SlackConfig) (*SlackResponse, error) {
	// In a real implementation, this would call Slack API
	// For now, return mock data
	mockChannels := []SlackChannel{
		{ID: "C1234567890", Name: "general", IsChannel: true, IsGeneral: true},
		{ID: "C1234567891", Name: "random", IsChannel: true},
		{ID: "C1234567892", Name: "development", IsChannel: true, IsPrivate: true},
	}

	return &SlackResponse{
		Operation: "list_channels",
		Success:   true,
		Data:      map[string]interface{}{"channels": mockChannels},
	}, nil
}

// executeUploadFile uploads a file to Slack
func (e *SlackExecutor) executeUploadFile(ctx context.Context, config *SlackConfig) (*SlackResponse, error) {
	// In a real implementation, this would handle file uploads
	return &SlackResponse{
		Operation: "upload_file",
		Success:   true,
		Channel:   config.Channel,
		Data:      map[string]interface{}{"message": "File upload not implemented in mock"},
	}, nil
}
