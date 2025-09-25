package nodes

import (
	"context"
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"n8n-pro/pkg/errors"
	"n8n-pro/pkg/logger"
)

// TransformExecutor implements data transformation operations
type TransformExecutor struct {
	logger logger.Logger
}

// TransformOperation represents the type of transformation to perform
type TransformOperation struct {
	Type       string                 `json:"type"`
	Field      string                 `json:"field,omitempty"`
	Value      interface{}            `json:"value,omitempty"`
	Options    map[string]interface{} `json:"options,omitempty"`
	Expression string                 `json:"expression,omitempty"`
	Mapping    map[string]string      `json:"mapping,omitempty"`
}

// TransformConfig represents the configuration for transform node
type TransformConfig struct {
	Operations []TransformOperation `json:"operations"`
	Mode       string              `json:"mode"` // "individual" or "batch"
}

// TransformResponse represents the result of transformation
type TransformResponse struct {
	Success      bool                   `json:"success"`
	Data         interface{}            `json:"data"`
	ItemsCount   int                    `json:"items_count"`
	Duration     int64                  `json:"duration_ms"`
	Timestamp    int64                  `json:"timestamp"`
	Operations   []string               `json:"operations_applied"`
	Error        string                 `json:"error,omitempty"`
}

// NewTransformExecutor creates a new transform node executor
func NewTransformExecutor() *TransformExecutor {
	return &TransformExecutor{
		logger: logger.New("transform-node"),
	}
}

// Execute performs the data transformation
func (t *TransformExecutor) Execute(ctx context.Context, parameters map[string]interface{}, inputData interface{}) (interface{}, error) {
	start := time.Now()

	// Parse configuration
	config, err := t.parseConfig(parameters)
	if err != nil {
		return t.createErrorResponse(start, fmt.Sprintf("Invalid configuration: %v", err)), err
	}

	t.logger.Debug("Executing transform operations", "operations_count", len(config.Operations), "mode", config.Mode)

	// Apply transformations
	result, appliedOps, err := t.applyTransformations(inputData, config)
	if err != nil {
		return t.createErrorResponse(start, fmt.Sprintf("Transform failed: %v", err)), err
	}

	// Create response
	response := &TransformResponse{
		Success:      true,
		Data:         result,
		ItemsCount:   t.countItems(result),
		Duration:     time.Since(start).Milliseconds(),
		Timestamp:    time.Now().Unix(),
		Operations:   appliedOps,
	}

	t.logger.Debug("Transform completed", "duration", response.Duration, "items", response.ItemsCount)

	return response, nil
}

// parseConfig parses the node parameters into transform configuration
func (t *TransformExecutor) parseConfig(parameters map[string]interface{}) (*TransformConfig, error) {
	config := &TransformConfig{
		Mode: "individual", // default mode
	}

	// Parse mode
	if mode, ok := parameters["mode"].(string); ok {
		config.Mode = mode
	}

	// Parse operations
	if ops, ok := parameters["operations"].([]interface{}); ok {
		for _, op := range ops {
			if opMap, ok := op.(map[string]interface{}); ok {
				operation := TransformOperation{}

				if opType, ok := opMap["type"].(string); ok {
					operation.Type = opType
				}

				if field, ok := opMap["field"].(string); ok {
					operation.Field = field
				}

				if value, exists := opMap["value"]; exists {
					operation.Value = value
				}

				if expr, ok := opMap["expression"].(string); ok {
					operation.Expression = expr
				}

				if options, ok := opMap["options"].(map[string]interface{}); ok {
					operation.Options = options
				}

				if mapping, ok := opMap["mapping"].(map[string]interface{}); ok {
					operation.Mapping = make(map[string]string)
					for k, v := range mapping {
						if strV, ok := v.(string); ok {
							operation.Mapping[k] = strV
						}
					}
				}

				config.Operations = append(config.Operations, operation)
			}
		}
	}

	if len(config.Operations) == 0 {
		return nil, errors.NewValidationError("At least one operation is required")
	}

	return config, nil
}

// applyTransformations applies all transformation operations
func (t *TransformExecutor) applyTransformations(inputData interface{}, config *TransformConfig) (interface{}, []string, error) {
	var appliedOps []string
	data := inputData

	for _, operation := range config.Operations {
		result, err := t.applyOperation(data, operation)
		if err != nil {
			return nil, appliedOps, fmt.Errorf("operation %s failed: %w", operation.Type, err)
		}
		data = result
		appliedOps = append(appliedOps, operation.Type)
	}

	return data, appliedOps, nil
}

// applyOperation applies a single transformation operation
func (t *TransformExecutor) applyOperation(data interface{}, op TransformOperation) (interface{}, error) {
	switch op.Type {
	case "set_field":
		return t.setField(data, op.Field, op.Value)
	case "remove_field":
		return t.removeField(data, op.Field)
	case "rename_field":
		return t.renameField(data, op.Field, t.getStringValue(op.Value))
	case "map_values":
		return t.mapValues(data, op.Field, op.Mapping)
	case "filter_array":
		return t.filterArray(data, op.Expression)
	case "transform_text":
		return t.transformText(data, op.Field, op.Options)
	case "convert_type":
		return t.convertType(data, op.Field, t.getStringValue(op.Value))
	case "extract_field":
		return t.extractField(data, op.Field, op.Expression)
	case "merge_objects":
		return t.mergeObjects(data, op.Value)
	case "group_by":
		return t.groupBy(data, op.Field)
	case "sort":
		return t.sortData(data, op.Field, op.Options)
	case "aggregate":
		return t.aggregate(data, op.Field, op.Options)
	default:
		return nil, fmt.Errorf("unsupported operation type: %s", op.Type)
	}
}

// setField sets a field value in the data
func (t *TransformExecutor) setField(data interface{}, field string, value interface{}) (interface{}, error) {
	switch d := data.(type) {
	case map[string]interface{}:
		result := make(map[string]interface{})
		for k, v := range d {
			result[k] = v
		}
		result[field] = value
		return result, nil
	case []interface{}:
		var result []interface{}
		for _, item := range d {
			transformed, err := t.setField(item, field, value)
			if err != nil {
				return nil, err
			}
			result = append(result, transformed)
		}
		return result, nil
	default:
		return nil, fmt.Errorf("cannot set field on non-object/array data")
	}
}

// removeField removes a field from the data
func (t *TransformExecutor) removeField(data interface{}, field string) (interface{}, error) {
	switch d := data.(type) {
	case map[string]interface{}:
		result := make(map[string]interface{})
		for k, v := range d {
			if k != field {
				result[k] = v
			}
		}
		return result, nil
	case []interface{}:
		var result []interface{}
		for _, item := range d {
			transformed, err := t.removeField(item, field)
			if err != nil {
				return nil, err
			}
			result = append(result, transformed)
		}
		return result, nil
	default:
		return nil, fmt.Errorf("cannot remove field from non-object/array data")
	}
}

// renameField renames a field in the data
func (t *TransformExecutor) renameField(data interface{}, oldField, newField string) (interface{}, error) {
	switch d := data.(type) {
	case map[string]interface{}:
		result := make(map[string]interface{})
		for k, v := range d {
			if k == oldField {
				result[newField] = v
			} else {
				result[k] = v
			}
		}
		return result, nil
	case []interface{}:
		var result []interface{}
		for _, item := range d {
			transformed, err := t.renameField(item, oldField, newField)
			if err != nil {
				return nil, err
			}
			result = append(result, transformed)
		}
		return result, nil
	default:
		return nil, fmt.Errorf("cannot rename field in non-object/array data")
	}
}

// mapValues maps values based on a mapping configuration
func (t *TransformExecutor) mapValues(data interface{}, field string, mapping map[string]string) (interface{}, error) {
	switch d := data.(type) {
	case map[string]interface{}:
		result := make(map[string]interface{})
		for k, v := range d {
			if k == field {
				if strV, ok := v.(string); ok {
					if mappedValue, exists := mapping[strV]; exists {
						result[k] = mappedValue
					} else {
						result[k] = v // Keep original if no mapping found
					}
				} else {
					result[k] = v
				}
			} else {
				result[k] = v
			}
		}
		return result, nil
	case []interface{}:
		var result []interface{}
		for _, item := range d {
			transformed, err := t.mapValues(item, field, mapping)
			if err != nil {
				return nil, err
			}
			result = append(result, transformed)
		}
		return result, nil
	default:
		return nil, fmt.Errorf("cannot map values in non-object/array data")
	}
}

// transformText performs text transformations
func (t *TransformExecutor) transformText(data interface{}, field string, options map[string]interface{}) (interface{}, error) {
	operation := t.getStringValue(options["operation"])
	
	transform := func(text string) string {
		switch operation {
		case "uppercase":
			return strings.ToUpper(text)
		case "lowercase":
			return strings.ToLower(text)
		case "trim":
			return strings.TrimSpace(text)
		case "replace":
			pattern := t.getStringValue(options["pattern"])
			replacement := t.getStringValue(options["replacement"])
			if useRegex, ok := options["regex"].(bool); ok && useRegex {
				re := regexp.MustCompile(pattern)
				return re.ReplaceAllString(text, replacement)
			}
			return strings.ReplaceAll(text, pattern, replacement)
		default:
			return text
		}
	}

	return t.applyToStringField(data, field, transform)
}

// convertType converts field type
func (t *TransformExecutor) convertType(data interface{}, field, targetType string) (interface{}, error) {
	convert := func(value interface{}) (interface{}, error) {
		switch targetType {
		case "string":
			return fmt.Sprintf("%v", value), nil
		case "number":
			if str, ok := value.(string); ok {
				if num, err := strconv.ParseFloat(str, 64); err == nil {
					return num, nil
				}
			}
			if reflect.TypeOf(value).Kind() == reflect.Float64 {
				return value, nil
			}
			return nil, fmt.Errorf("cannot convert to number")
		case "boolean":
			if str, ok := value.(string); ok {
				return strings.ToLower(str) == "true", nil
			}
			if b, ok := value.(bool); ok {
				return b, nil
			}
			return false, nil
		default:
			return value, nil
		}
	}

	return t.applyToField(data, field, convert)
}

// Helper functions

func (t *TransformExecutor) getStringValue(value interface{}) string {
	if str, ok := value.(string); ok {
		return str
	}
	return fmt.Sprintf("%v", value)
}

func (t *TransformExecutor) applyToStringField(data interface{}, field string, transform func(string) string) (interface{}, error) {
	fn := func(value interface{}) (interface{}, error) {
		if str, ok := value.(string); ok {
			return transform(str), nil
		}
		return value, nil
	}
	return t.applyToField(data, field, fn)
}

func (t *TransformExecutor) applyToField(data interface{}, field string, transform func(interface{}) (interface{}, error)) (interface{}, error) {
	switch d := data.(type) {
	case map[string]interface{}:
		result := make(map[string]interface{})
		for k, v := range d {
			if k == field {
				transformed, err := transform(v)
				if err != nil {
					return nil, err
				}
				result[k] = transformed
			} else {
				result[k] = v
			}
		}
		return result, nil
	case []interface{}:
		var result []interface{}
		for _, item := range d {
			transformed, err := t.applyToField(item, field, transform)
			if err != nil {
				return nil, err
			}
			result = append(result, transformed)
		}
		return result, nil
	default:
		return nil, fmt.Errorf("cannot apply field transformation to non-object/array data")
	}
}

// Stub implementations for complex operations
func (t *TransformExecutor) filterArray(data interface{}, expression string) (interface{}, error) {
	// Simplified filter implementation
	return data, nil
}

func (t *TransformExecutor) extractField(data interface{}, field, expression string) (interface{}, error) {
	// Simplified extract implementation
	return data, nil
}

func (t *TransformExecutor) mergeObjects(data, mergeData interface{}) (interface{}, error) {
	// Simplified merge implementation
	return data, nil
}

func (t *TransformExecutor) groupBy(data interface{}, field string) (interface{}, error) {
	// Simplified group by implementation
	return data, nil
}

func (t *TransformExecutor) sortData(data interface{}, field string, options map[string]interface{}) (interface{}, error) {
	// Simplified sort implementation
	return data, nil
}

func (t *TransformExecutor) aggregate(data interface{}, field string, options map[string]interface{}) (interface{}, error) {
	// Simplified aggregate implementation
	return data, nil
}

// countItems counts the number of items in the result
func (t *TransformExecutor) countItems(data interface{}) int {
	switch d := data.(type) {
	case []interface{}:
		return len(d)
	case map[string]interface{}:
		return 1
	default:
		return 1
	}
}

// createErrorResponse creates an error response
func (t *TransformExecutor) createErrorResponse(startTime time.Time, errorMsg string) *TransformResponse {
	return &TransformResponse{
		Success:   false,
		Error:     errorMsg,
		Duration:  time.Since(startTime).Milliseconds(),
		Timestamp: time.Now().Unix(),
	}
}