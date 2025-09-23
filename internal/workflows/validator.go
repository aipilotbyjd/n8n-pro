package workflows

import (
	"context"
	"fmt"
	"strings"

	"n8n-pro/internal/auth"
	"n8n-pro/pkg/errors"
	"n8n-pro/pkg/logger"
)

// DefaultValidator implements the Validator interface
type DefaultValidator struct {
	authService *auth.Service
	logger      logger.Logger
}

// NewDefaultValidator creates a new default validator
func NewDefaultValidator(authService *auth.Service) Validator {
	return &DefaultValidator{
		authService: authService,
		logger:      logger.New("workflow-validator"),
	}
}

// ValidateWorkflow validates a workflow definition
func (v *DefaultValidator) ValidateWorkflow(ctx context.Context, workflow *Workflow) error {
	if workflow == nil {
		return errors.NewValidationError("workflow cannot be nil")
	}

	// Basic field validation
	if err := v.validateBasicFields(workflow); err != nil {
		return err
	}

	// Validate nodes
	if err := v.validateNodes(workflow.Nodes); err != nil {
		return err
	}

	// Validate connections
	if err := v.validateConnections(workflow.Nodes, workflow.Connections); err != nil {
		return err
	}

	// Validate variables
	if err := v.validateVariables(workflow.Variables); err != nil {
		return err
	}

	// Validate triggers
	if err := v.validateTriggers(workflow.Triggers, workflow.Nodes); err != nil {
		return err
	}

	// Validate workflow configuration
	if err := v.validateWorkflowConfig(&workflow.Config); err != nil {
		return err
	}

	// Check for circular dependencies
	if err := v.checkCircularDependencies(workflow.Nodes, workflow.Connections); err != nil {
		return err
	}

	// Validate that workflow has at least one trigger or can be manually triggered
	if err := v.validateExecutability(workflow); err != nil {
		return err
	}

	v.logger.InfoContext(ctx, "Workflow validation passed", "workflow_id", workflow.ID, "name", workflow.Name)
	return nil
}

// ValidateExecution validates a workflow execution
func (v *DefaultValidator) ValidateExecution(ctx context.Context, execution *WorkflowExecution) error {
	if execution == nil {
		return errors.NewValidationError("execution cannot be nil")
	}

	// Basic field validation
	if execution.WorkflowID == "" {
		return errors.NewValidationError("workflow ID is required")
	}

	if execution.TeamID == "" {
		return errors.NewValidationError("team ID is required")
	}

	// Validate status
	validStatuses := map[ExecutionStatus]bool{
		ExecutionStatusPending:   true,
		ExecutionStatusRunning:   true,
		ExecutionStatusCompleted: true,
		ExecutionStatusFailed:    true,
		ExecutionStatusCanceled:  true,
		ExecutionStatusTimeout:   true,
		ExecutionStatusRetrying:  true,
		ExecutionStatusWaiting:   true,
		ExecutionStatusPaused:    true,
	}

	if !validStatuses[execution.Status] {
		return errors.NewValidationError(fmt.Sprintf("invalid execution status: %s", execution.Status))
	}

	// Validate mode
	if execution.Mode == "" {
		execution.Mode = "manual" // Default to manual
	}

	validModes := map[string]bool{
		"manual":   true,
		"webhook":  true,
		"schedule": true,
		"trigger":  true,
		"retry":    true,
	}

	if !validModes[execution.Mode] {
		return errors.NewValidationError(fmt.Sprintf("invalid execution mode: %s", execution.Mode))
	}

	v.logger.InfoContext(ctx, "Execution validation passed", "execution_id", execution.ID, "workflow_id", execution.WorkflowID)
	return nil
}

// ValidatePermissions validates user permissions for workflow operations
func (v *DefaultValidator) ValidatePermissions(ctx context.Context, userID, teamID, workflowID string, action string) error {
	if userID == "" {
		return errors.NewUnauthorizedError("user ID is required")
	}

	// Get user details
	user, err := v.authService.GetUserByID(ctx, userID)
	if err != nil {
		v.logger.Error("Failed to get user for permission validation", "user_id", userID, "error", err)
		return errors.NewUnauthorizedError("user not found")
	}

	if !user.Active {
		return errors.NewUnauthorizedError("user account is disabled")
	}

	// Check team membership
	if teamID != "" && user.TeamID != teamID {
		return errors.NewForbiddenError("user does not belong to the specified team")
	}

	// Role-based permissions
	switch action {
	case "create", "update", "delete":
		// Only admins and editors can modify workflows
		if user.Role != "admin" && user.Role != "editor" {
			return errors.NewForbiddenError("insufficient permissions to modify workflows")
		}
	case "execute":
		// All active users can execute workflows they have access to
		if user.Role == "viewer" {
			// Viewers might have restricted execution permissions
			// This could be made configurable
		}
	case "read", "list":
		// All active users can read workflows in their team
		break
	default:
		return errors.NewValidationError(fmt.Sprintf("unknown action: %s", action))
	}

	v.logger.DebugContext(ctx, "Permission validation passed",
		"user_id", userID,
		"team_id", teamID,
		"workflow_id", workflowID,
		"action", action,
		"user_role", user.Role,
	)

	return nil
}

// Private validation methods

func (v *DefaultValidator) validateBasicFields(workflow *Workflow) error {
	if workflow.Name == "" {
		return errors.NewValidationError("workflow name is required")
	}

	if len(workflow.Name) > 255 {
		return errors.NewValidationError("workflow name cannot exceed 255 characters")
	}

	if workflow.TeamID == "" {
		return errors.NewValidationError("team ID is required")
	}

	if workflow.OwnerID == "" {
		return errors.NewValidationError("owner ID is required")
	}

	// Validate status
	validStatuses := map[WorkflowStatus]bool{
		WorkflowStatusActive:   true,
		WorkflowStatusInactive: true,
		WorkflowStatusDraft:    true,
		WorkflowStatusArchived: true,
	}

	if !validStatuses[workflow.Status] {
		return errors.NewValidationError(fmt.Sprintf("invalid workflow status: %s", workflow.Status))
	}

	return nil
}

func (v *DefaultValidator) validateNodes(nodes []Node) error {
	if len(nodes) == 0 {
		return errors.NewValidationError("workflow must have at least one node")
	}

	nodeIDs := make(map[string]bool)
	nodeNames := make(map[string]bool)

	for i, node := range nodes {
		// Check for duplicate IDs
		if nodeIDs[node.ID] {
			return errors.NewValidationError(fmt.Sprintf("duplicate node ID: %s", node.ID))
		}
		nodeIDs[node.ID] = true

		// Check for duplicate names
		if nodeNames[node.Name] {
			return errors.NewValidationError(fmt.Sprintf("duplicate node name: %s", node.Name))
		}
		nodeNames[node.Name] = true

		// Validate individual node
		if err := v.validateNode(&nodes[i]); err != nil {
			return errors.Wrap(err, errors.ErrorTypeValidation, errors.CodeInvalidInput,
				fmt.Sprintf("validation failed for node %s", node.ID))
		}
	}

	return nil
}

func (v *DefaultValidator) validateNode(node *Node) error {
	if node.ID == "" {
		return errors.NewValidationError("node ID is required")
	}

	if node.Name == "" {
		return errors.NewValidationError("node name is required")
	}

	if len(node.Name) > 255 {
		return errors.NewValidationError("node name cannot exceed 255 characters")
	}

	// Validate node type
	validTypes := map[NodeType]bool{
		NodeTypeTrigger:    true,
		NodeTypeAction:     true,
		NodeTypeCondition:  true,
		NodeTypeTransform:  true,
		NodeTypeLoop:       true,
		NodeTypeWait:       true,
		NodeTypeSubflow:    true,
		NodeTypeCode:       true,
		NodeTypeWebhook:    true,
		NodeTypeHTTP:       true,
		NodeTypeDatabase:   true,
		NodeTypeEmail:      true,
		NodeTypeSlack:      true,
		NodeTypeGoogleDocs: true,
	}

	if !validTypes[node.Type] {
		return errors.NewValidationError(fmt.Sprintf("invalid node type: %s", node.Type))
	}

	// Validate retry settings
	if node.MaxTries < 1 || node.MaxTries > 5 {
		return errors.NewValidationError("max tries must be between 1 and 5")
	}

	if node.WaitBetweenTries < 0 || node.WaitBetweenTries > 300000 { // 5 minutes max
		return errors.NewValidationError("wait between tries must be between 0 and 300000 milliseconds")
	}

	// Type-specific validation
	switch node.Type {
	case NodeTypeCode:
		if node.Code == "" {
			return errors.NewValidationError("code is required for code nodes")
		}
		if node.Language == "" {
			return errors.NewValidationError("language is required for code nodes")
		}
		if node.Language != "javascript" && node.Language != "python" {
			return errors.NewValidationError("language must be 'javascript' or 'python'")
		}
	case NodeTypeWebhook:
		if node.HTTPMethod != "" {
			validMethods := map[string]bool{
				"GET": true, "POST": true, "PUT": true, "DELETE": true, "PATCH": true,
			}
			if !validMethods[strings.ToUpper(node.HTTPMethod)] {
				return errors.NewValidationError(fmt.Sprintf("invalid HTTP method: %s", node.HTTPMethod))
			}
		}
	}

	return nil
}

func (v *DefaultValidator) validateConnections(nodes []Node, connections []Connection) error {
	// Create node ID map for quick lookup
	nodeMap := make(map[string]*Node)
	for i := range nodes {
		nodeMap[nodes[i].ID] = &nodes[i]
	}

	connectionIDs := make(map[string]bool)

	for _, conn := range connections {
		// Check for duplicate connection IDs
		if connectionIDs[conn.ID] {
			return errors.NewValidationError(fmt.Sprintf("duplicate connection ID: %s", conn.ID))
		}
		connectionIDs[conn.ID] = true

		// Validate connection fields
		if conn.SourceNode == "" {
			return errors.NewValidationError("connection source node is required")
		}

		if conn.TargetNode == "" {
			return errors.NewValidationError("connection target node is required")
		}

		// Check that referenced nodes exist
		if _, exists := nodeMap[conn.SourceNode]; !exists {
			return errors.NewValidationError(fmt.Sprintf("connection references non-existent source node: %s", conn.SourceNode))
		}

		if _, exists := nodeMap[conn.TargetNode]; !exists {
			return errors.NewValidationError(fmt.Sprintf("connection references non-existent target node: %s", conn.TargetNode))
		}

		// Validate connection type
		if conn.Type != "main" && conn.Type != "error" {
			return errors.NewValidationError(fmt.Sprintf("invalid connection type: %s", conn.Type))
		}

		// Prevent self-connections
		if conn.SourceNode == conn.TargetNode {
			return errors.NewValidationError("node cannot connect to itself")
		}
	}

	return nil
}

func (v *DefaultValidator) validateVariables(variables []Variable) error {
	variableKeys := make(map[string]bool)

	for _, variable := range variables {
		if variable.Key == "" {
			return errors.NewValidationError("variable key is required")
		}

		if len(variable.Key) > 100 {
			return errors.NewValidationError("variable key cannot exceed 100 characters")
		}

		// Check for duplicate keys
		if variableKeys[variable.Key] {
			return errors.NewValidationError(fmt.Sprintf("duplicate variable key: %s", variable.Key))
		}
		variableKeys[variable.Key] = true

		// Validate variable type
		validTypes := map[string]bool{
			"string": true, "number": true, "boolean": true, "object": true, "array": true,
		}

		if variable.Type != "" && !validTypes[variable.Type] {
			return errors.NewValidationError(fmt.Sprintf("invalid variable type: %s", variable.Type))
		}

		// Check required variables have values
		if variable.Required && variable.Value == nil && variable.DefaultValue == nil {
			return errors.NewValidationError(fmt.Sprintf("required variable %s must have a value or default value", variable.Key))
		}
	}

	return nil
}

func (v *DefaultValidator) validateTriggers(triggers []Trigger, nodes []Node) error {
	// Create node ID map for quick lookup
	nodeMap := make(map[string]*Node)
	for i := range nodes {
		nodeMap[nodes[i].ID] = &nodes[i]
	}

	triggerIDs := make(map[string]bool)

	for _, trigger := range triggers {
		// Check for duplicate trigger IDs
		if triggerIDs[trigger.ID] {
			return errors.NewValidationError(fmt.Sprintf("duplicate trigger ID: %s", trigger.ID))
		}
		triggerIDs[trigger.ID] = true

		// Validate trigger fields
		if trigger.NodeID == "" {
			return errors.NewValidationError("trigger node ID is required")
		}

		// Check that referenced node exists
		node, exists := nodeMap[trigger.NodeID]
		if !exists {
			return errors.NewValidationError(fmt.Sprintf("trigger references non-existent node: %s", trigger.NodeID))
		}

		// Check that the referenced node is a trigger node
		if node.Type != NodeTypeTrigger {
			return errors.NewValidationError(fmt.Sprintf("trigger can only reference trigger nodes, but node %s is type %s", trigger.NodeID, node.Type))
		}

		// Validate trigger type
		validTypes := map[TriggerType]bool{
			TriggerTypeWebhook:   true,
			TriggerTypeSchedule:  true,
			TriggerTypeManual:    true,
			TriggerTypeEmail:     true,
			TriggerTypeFileWatch: true,
			TriggerTypeDatabase:  true,
			TriggerTypeAPI:       true,
		}

		if !validTypes[trigger.Type] {
			return errors.NewValidationError(fmt.Sprintf("invalid trigger type: %s", trigger.Type))
		}

		// Type-specific validation
		if err := v.validateTriggerConfig(trigger.Type, &trigger.Config); err != nil {
			return errors.Wrap(err, errors.ErrorTypeValidation, errors.CodeInvalidInput,
				fmt.Sprintf("validation failed for trigger %s", trigger.ID))
		}
	}

	return nil
}

func (v *DefaultValidator) validateTriggerConfig(triggerType TriggerType, config *TriggerConfig) error {
	switch triggerType {
	case TriggerTypeSchedule:
		if config.CronExpression == "" {
			return errors.NewValidationError("cron expression is required for schedule triggers")
		}
		// TODO: Add cron expression validation
	case TriggerTypeWebhook:
		if config.WebhookMethod != "" {
			validMethods := map[string]bool{
				"GET": true, "POST": true, "PUT": true, "DELETE": true, "PATCH": true,
			}
			if !validMethods[strings.ToUpper(config.WebhookMethod)] {
				return errors.NewValidationError(fmt.Sprintf("invalid webhook method: %s", config.WebhookMethod))
			}
		}
	case TriggerTypeEmail:
		if config.EmailAddress == "" {
			return errors.NewValidationError("email address is required for email triggers")
		}
	case TriggerTypeFileWatch:
		if config.WatchPath == "" {
			return errors.NewValidationError("watch path is required for file watch triggers")
		}
	case TriggerTypeDatabase:
		if config.DatabaseConnection == "" {
			return errors.NewValidationError("database connection is required for database triggers")
		}
		if config.PollInterval <= 0 {
			return errors.NewValidationError("poll interval must be greater than 0")
		}
	}

	return nil
}

func (v *DefaultValidator) validateWorkflowConfig(config *WorkflowConfig) error {
	if config.Timeout <= 0 || config.Timeout > 86400 {
		return errors.NewValidationError("timeout must be between 1 and 86400 seconds")
	}

	if config.MaxExecutionTime <= 0 || config.MaxExecutionTime > 86400 {
		return errors.NewValidationError("max execution time must be between 1 and 86400 seconds")
	}

	if config.MaxRetryAttempts < 0 || config.MaxRetryAttempts > 10 {
		return errors.NewValidationError("max retry attempts must be between 0 and 10")
	}

	if config.RetryInterval <= 0 || config.RetryInterval > 3600 {
		return errors.NewValidationError("retry interval must be between 1 and 3600 seconds")
	}

	if config.MaxConcurrentRuns <= 0 || config.MaxConcurrentRuns > 100 {
		return errors.NewValidationError("max concurrent runs must be between 1 and 100")
	}

	if config.Priority < 1 || config.Priority > 10 {
		return errors.NewValidationError("priority must be between 1 and 10")
	}

	// Validate log level
	validLogLevels := map[string]bool{
		"debug": true, "info": true, "warn": true, "error": true,
	}

	if !validLogLevels[config.LogLevel] {
		return errors.NewValidationError(fmt.Sprintf("invalid log level: %s", config.LogLevel))
	}

	// Validate execution policy
	if config.ExecutionPolicy != "parallel" && config.ExecutionPolicy != "sequential" {
		return errors.NewValidationError("execution policy must be 'parallel' or 'sequential'")
	}

	return nil
}

func (v *DefaultValidator) checkCircularDependencies(nodes []Node, connections []Connection) error {
	// Build adjacency list
	graph := make(map[string][]string)
	for _, conn := range connections {
		if conn.Enabled {
			graph[conn.SourceNode] = append(graph[conn.SourceNode], conn.TargetNode)
		}
	}

	// Check for cycles using DFS
	visited := make(map[string]bool)
	recStack := make(map[string]bool)

	var hasCycle func(string) bool
	hasCycle = func(nodeID string) bool {
		visited[nodeID] = true
		recStack[nodeID] = true

		for _, neighbor := range graph[nodeID] {
			if !visited[neighbor] {
				if hasCycle(neighbor) {
					return true
				}
			} else if recStack[neighbor] {
				return true
			}
		}

		recStack[nodeID] = false
		return false
	}

	for _, node := range nodes {
		if !visited[node.ID] {
			if hasCycle(node.ID) {
				return errors.NewValidationError("workflow contains circular dependencies")
			}
		}
	}

	return nil
}

func (v *DefaultValidator) validateExecutability(workflow *Workflow) error {
	// Check if workflow has at least one trigger node or can be manually executed
	hasTrigger := false
	hasStartNode := false

	for _, node := range workflow.Nodes {
		if node.Type == NodeTypeTrigger {
			hasTrigger = true
			break
		}
		// Check for nodes that can serve as entry points
		if !node.Disabled {
			hasStartNode = true
		}
	}

	// Check if any triggers are enabled
	hasEnabledTrigger := false
	for _, trigger := range workflow.Triggers {
		if trigger.Enabled {
			hasEnabledTrigger = true
			break
		}
	}

	// Workflow must either have enabled triggers or be manually executable
	if !hasTrigger && !hasStartNode {
		return errors.NewValidationError("workflow must have at least one trigger node or executable node")
	}

	// If workflow has triggers, at least one should be enabled for automatic execution
	if hasTrigger && !hasEnabledTrigger && workflow.Status == WorkflowStatusActive {
		v.logger.Warn("Active workflow has no enabled triggers - can only be executed manually",
			"workflow_id", workflow.ID,
			"name", workflow.Name,
		)
	}

	return nil
}