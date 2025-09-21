package errors

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAppError(t *testing.T) {
	t.Run("New creates error with correct fields", func(t *testing.T) {
		err := New(ErrorTypeValidation, CodeInvalidInput, "test message")
		
		assert.Equal(t, ErrorTypeValidation, err.Type)
		assert.Equal(t, CodeInvalidInput, err.Code)
		assert.Equal(t, "test message", err.Message)
		assert.NotEmpty(t, err.StackTrace)
		assert.False(t, err.Retryable)
		assert.NotNil(t, err.Context)
	})

	t.Run("Newf creates error with formatted message", func(t *testing.T) {
		err := Newf(ErrorTypeValidation, CodeInvalidInput, "test %s %d", "message", 123)
		
		assert.Equal(t, "test message 123", err.Message)
	})

	t.Run("Error method returns formatted string", func(t *testing.T) {
		err := New(ErrorTypeValidation, CodeInvalidInput, "test message")
		
		expected := fmt.Sprintf("%s: %s", CodeInvalidInput, "test message")
		assert.Equal(t, expected, err.Error())
	})

	t.Run("Error method with details", func(t *testing.T) {
		err := New(ErrorTypeValidation, CodeInvalidInput, "test message").WithDetails("extra details")
		
		expected := fmt.Sprintf("%s: %s - %s", CodeInvalidInput, "test message", "extra details")
		assert.Equal(t, expected, err.Error())
	})

	t.Run("WithContext adds context", func(t *testing.T) {
		err := New(ErrorTypeValidation, CodeInvalidInput, "test message")
		err.WithContext("key", "value")
		
		assert.Equal(t, "value", err.Context["key"])
	})

	t.Run("WithCause sets underlying cause", func(t *testing.T) {
		cause := errors.New("original error")
		err := New(ErrorTypeValidation, CodeInvalidInput, "test message").WithCause(cause)
		
		assert.Equal(t, cause, err.Cause)
		assert.Equal(t, cause, err.Unwrap())
	})

	t.Run("WithDetails adds details", func(t *testing.T) {
		err := New(ErrorTypeValidation, CodeInvalidInput, "test message").WithDetails("extra info")
		
		assert.Equal(t, "extra info", err.Details)
	})

	t.Run("WithStackTrace captures stack trace", func(t *testing.T) {
		err := New(ErrorTypeValidation, CodeInvalidInput, "test message").WithStackTrace()
		
		assert.NotEmpty(t, err.StackTrace)
		assert.Contains(t, err.StackTrace, "TestAppError")
	})
}

func TestWrapError(t *testing.T) {
	t.Run("Wrap nil error returns nil", func(t *testing.T) {
		err := Wrap(nil, ErrorTypeInternal, CodeInternal, "test")
		assert.Nil(t, err)
	})

	t.Run("Wrap regular error", func(t *testing.T) {
		original := errors.New("original error")
		wrapped := Wrap(original, ErrorTypeInternal, CodeInternal, "wrapped message")
		
		assert.Equal(t, ErrorTypeInternal, wrapped.Type)
		assert.Equal(t, CodeInternal, wrapped.Code)
		assert.Equal(t, "wrapped message", wrapped.Message)
		assert.Equal(t, original, wrapped.Cause)
	})

	t.Run("Wrap AppError preserves retryable flag", func(t *testing.T) {
		original := New(ErrorTypeTimeout, CodeTimeout, "timeout").SetRetryable(true)
		wrapped := Wrap(original, ErrorTypeInternal, CodeInternal, "wrapped")
		
		assert.True(t, wrapped.Retryable)
		assert.Equal(t, original, wrapped.Cause)
	})

	t.Run("Wrapf with formatted message", func(t *testing.T) {
		original := errors.New("original")
		wrapped := Wrapf(original, ErrorTypeInternal, CodeInternal, "wrapped %s %d", "message", 123)
		
		assert.Equal(t, "wrapped message 123", wrapped.Message)
		assert.Equal(t, original, wrapped.Cause)
	})
}

func TestErrorConstructors(t *testing.T) {
	t.Run("ValidationError", func(t *testing.T) {
		err := ValidationError(CodeInvalidInput, "invalid data")
		
		assert.Equal(t, ErrorTypeValidation, err.Type)
		assert.Equal(t, CodeInvalidInput, err.Code)
		assert.Equal(t, "invalid data", err.Message)
	})

	t.Run("AuthenticationError", func(t *testing.T) {
		err := AuthenticationError(CodeInvalidCredentials, "bad credentials")
		
		assert.Equal(t, ErrorTypeAuthentication, err.Type)
		assert.Equal(t, CodeInvalidCredentials, err.Code)
	})

	t.Run("AuthorizationError", func(t *testing.T) {
		err := AuthorizationError(CodeInsufficientPermissions, "no access")
		
		assert.Equal(t, ErrorTypeAuthorization, err.Type)
		assert.Equal(t, CodeInsufficientPermissions, err.Code)
	})

	t.Run("NotFoundError", func(t *testing.T) {
		err := NotFoundError("workflow")
		
		assert.Equal(t, ErrorTypeNotFound, err.Type)
		assert.Equal(t, CodeResourceNotFound, err.Code)
		assert.Equal(t, "workflow not found", err.Message)
	})

	t.Run("ConflictError", func(t *testing.T) {
		err := ConflictError("workflow")
		
		assert.Equal(t, ErrorTypeConflict, err.Type)
		assert.Equal(t, CodeResourceExists, err.Code)
		assert.Equal(t, "workflow already exists", err.Message)
	})

	t.Run("InternalError", func(t *testing.T) {
		err := InternalError("system error")
		
		assert.Equal(t, ErrorTypeInternal, err.Type)
		assert.Equal(t, CodeInternal, err.Code)
		assert.NotEmpty(t, err.StackTrace)
	})

	t.Run("TimeoutError", func(t *testing.T) {
		err := TimeoutError("database")
		
		assert.Equal(t, ErrorTypeTimeout, err.Type)
		assert.Equal(t, CodeTimeout, err.Code)
		assert.Equal(t, "operation database timed out", err.Message)
	})

	t.Run("DatabaseError", func(t *testing.T) {
		cause := errors.New("connection failed")
		err := DatabaseError("insert", cause)
		
		assert.Equal(t, ErrorTypeDatabase, err.Type)
		assert.Equal(t, CodeDatabaseQuery, err.Code)
		assert.Equal(t, "database operation insert failed", err.Message)
		assert.Equal(t, cause, err.Cause)
	})

	t.Run("WorkflowError", func(t *testing.T) {
		workflowID := "wf-123"
		err := WorkflowError(workflowID, "execution failed")
		
		assert.Equal(t, ErrorTypeWorkflow, err.Type)
		assert.Equal(t, CodeWorkflowExecution, err.Code)
		assert.Equal(t, workflowID, err.Context["workflow_id"])
	})

	t.Run("NodeError", func(t *testing.T) {
		nodeID := "node-123"
		nodeType := "http"
		err := NodeError(nodeID, nodeType, "request failed")
		
		assert.Equal(t, ErrorTypeNode, err.Type)
		assert.Equal(t, CodeNodeExecution, err.Code)
		assert.Equal(t, nodeID, err.Context["node_id"])
		assert.Equal(t, nodeType, err.Context["node_type"])
	})
}

func TestGetAppError(t *testing.T) {
	t.Run("GetAppError from AppError", func(t *testing.T) {
		original := New(ErrorTypeValidation, CodeInvalidInput, "test")
		result := GetAppError(original)
		
		assert.Equal(t, original, result)
	})

	t.Run("GetAppError from wrapped AppError", func(t *testing.T) {
		appErr := New(ErrorTypeValidation, CodeInvalidInput, "test")
		wrapped := fmt.Errorf("wrapped: %w", appErr)
		result := GetAppError(wrapped)
		
		assert.Equal(t, appErr, result)
	})

	t.Run("GetAppError from regular error", func(t *testing.T) {
		regularErr := errors.New("regular error")
		result := GetAppError(regularErr)
		
		assert.Nil(t, result)
	})

	t.Run("GetAppError from nil", func(t *testing.T) {
		result := GetAppError(nil)
		assert.Nil(t, result)
	})
}

func TestHTTPStatusMapping(t *testing.T) {
	tests := []struct {
		errorType    ErrorType
		expectedCode int
	}{
		{ErrorTypeValidation, 400},
		{ErrorTypeAuthentication, 401},
		{ErrorTypeAuthorization, 403},
		{ErrorTypeNotFound, 404},
		{ErrorTypeTimeout, 408},
		{ErrorTypeConflict, 409},
		{ErrorTypeRateLimit, 429},
		{ErrorTypeInternal, 500},
		{ErrorTypeExternal, 500},
		{"unknown", 500},
	}

	for _, test := range tests {
		t.Run(string(test.errorType), func(t *testing.T) {
			err := New(test.errorType, CodeInternal, "test")
			assert.Equal(t, test.expectedCode, err.HTTPStatus())
		})
	}
}

func TestRetryable(t *testing.T) {
	t.Run("IsRetryable returns true for retryable types", func(t *testing.T) {
		retryableTypes := []ErrorType{
			ErrorTypeTimeout,
			ErrorTypeNetwork,
			ErrorTypeExternal,
			ErrorTypeRateLimit,
		}

		for _, errorType := range retryableTypes {
			err := New(errorType, CodeInternal, "test")
			assert.True(t, err.IsRetryable(), "Error type %s should be retryable", errorType)
		}
	})

	t.Run("IsRetryable returns false for non-retryable types", func(t *testing.T) {
		nonRetryableTypes := []ErrorType{
			ErrorTypeValidation,
			ErrorTypeAuthentication,
			ErrorTypeAuthorization,
			ErrorTypeNotFound,
		}

		for _, errorType := range nonRetryableTypes {
			err := New(errorType, CodeInternal, "test")
			assert.False(t, err.IsRetryable(), "Error type %s should not be retryable", errorType)
		}
	})

	t.Run("SetRetryable overrides default behavior", func(t *testing.T) {
		err := New(ErrorTypeValidation, CodeInvalidInput, "test").SetRetryable(true)
		assert.True(t, err.IsRetryable())

		err2 := New(ErrorTypeTimeout, CodeTimeout, "test").SetRetryable(false)
		assert.False(t, err2.IsRetryable())
	})

	t.Run("Explicit retryable flag takes precedence", func(t *testing.T) {
		err := New(ErrorTypeTimeout, CodeTimeout, "test")
		err.Retryable = true
		assert.True(t, err.IsRetryable())
	})
}

func TestErrorList(t *testing.T) {
	t.Run("NewErrorList creates empty list", func(t *testing.T) {
		list := NewErrorList()
		
		assert.NotNil(t, list.Errors)
		assert.Len(t, list.Errors, 0)
		assert.False(t, list.HasErrors())
	})

	t.Run("Add adds errors to list", func(t *testing.T) {
		list := NewErrorList()
		err1 := New(ErrorTypeValidation, CodeInvalidInput, "error 1")
		err2 := New(ErrorTypeValidation, CodeMissingField, "error 2")
		
		list.Add(err1)
		list.Add(err2)
		
		assert.Len(t, list.Errors, 2)
		assert.True(t, list.HasErrors())
		assert.Equal(t, err1, list.Errors[0])
		assert.Equal(t, err2, list.Errors[1])
	})

	t.Run("Add ignores nil errors", func(t *testing.T) {
		list := NewErrorList()
		list.Add(nil)
		
		assert.Len(t, list.Errors, 0)
		assert.False(t, list.HasErrors())
	})

	t.Run("Error method with no errors", func(t *testing.T) {
		list := NewErrorList()
		assert.Equal(t, "no errors", list.Error())
	})

	t.Run("Error method with single error", func(t *testing.T) {
		list := NewErrorList()
		err := New(ErrorTypeValidation, CodeInvalidInput, "test error")
		list.Add(err)
		
		assert.Equal(t, err.Error(), list.Error())
	})

	t.Run("Error method with multiple errors", func(t *testing.T) {
		list := NewErrorList()
		err1 := New(ErrorTypeValidation, CodeInvalidInput, "error 1")
		err2 := New(ErrorTypeValidation, CodeMissingField, "error 2")
		list.Add(err1)
		list.Add(err2)
		
		expected := fmt.Sprintf("multiple errors: [%s; %s]", err1.Error(), err2.Error())
		assert.Equal(t, expected, list.Error())
	})
}

func TestErrorChain(t *testing.T) {
	t.Run("NewChain creates empty chain", func(t *testing.T) {
		chain := NewChain()
		
		assert.NotNil(t, chain.errors)
		assert.Len(t, chain.errors, 0)
		assert.False(t, chain.HasErrors())
		assert.Nil(t, chain.First())
		assert.Nil(t, chain.Last())
	})

	t.Run("Add adds errors to chain", func(t *testing.T) {
		chain := NewChain()
		err1 := New(ErrorTypeValidation, CodeInvalidInput, "error 1")
		err2 := New(ErrorTypeValidation, CodeMissingField, "error 2")
		
		chain.Add(err1)
		chain.Add(err2)
		
		assert.Len(t, chain.errors, 2)
		assert.True(t, chain.HasErrors())
		assert.Equal(t, err1, chain.First())
		assert.Equal(t, err2, chain.Last())
		
		errors := chain.Errors()
		assert.Len(t, errors, 2)
		assert.Equal(t, err1, errors[0])
		assert.Equal(t, err2, errors[1])
	})

	t.Run("Add ignores nil errors", func(t *testing.T) {
		chain := NewChain()
		chain.Add(nil)
		
		assert.Len(t, chain.errors, 0)
		assert.False(t, chain.HasErrors())
	})
}

func TestSpecialErrorTypes(t *testing.T) {
	t.Run("HTTPError", func(t *testing.T) {
		httpErr := NewHTTPError(404, "not found")
		
		assert.Equal(t, 404, httpErr.StatusCode)
		assert.Equal(t, ErrorTypeExternal, httpErr.Type)
		assert.Equal(t, CodeExternalService, httpErr.Code)
		assert.Equal(t, "not found", httpErr.Message)
	})

	t.Run("NetworkError", func(t *testing.T) {
		netErr := NewNetworkError("connection failed")
		
		assert.Equal(t, ErrorTypeNetwork, netErr.Type)
		assert.Equal(t, CodeExternalService, netErr.Code)
		assert.Equal(t, "connection failed", netErr.Message)
	})

	t.Run("QuotaError", func(t *testing.T) {
		quotaErr := NewQuotaError("quota exceeded")
		
		assert.Equal(t, ErrorTypeRateLimit, quotaErr.Type)
		assert.Equal(t, CodeRateLimit, quotaErr.Code)
		assert.Equal(t, "quota exceeded", quotaErr.Message)
	})
}

func TestPredefinedErrors(t *testing.T) {
	t.Run("ErrInvalidInput", func(t *testing.T) {
		assert.Equal(t, ErrorTypeValidation, ErrInvalidInput.Type)
		assert.Equal(t, CodeInvalidInput, ErrInvalidInput.Code)
	})

	t.Run("ErrUnauthorized", func(t *testing.T) {
		assert.Equal(t, ErrorTypeAuthentication, ErrUnauthorized.Type)
		assert.Equal(t, CodeInvalidCredentials, ErrUnauthorized.Code)
	})

	t.Run("ErrForbidden", func(t *testing.T) {
		assert.Equal(t, ErrorTypeAuthorization, ErrForbidden.Type)
		assert.Equal(t, CodeInsufficientPermissions, ErrForbidden.Code)
	})

	t.Run("ErrTooManyRequests", func(t *testing.T) {
		assert.Equal(t, ErrorTypeRateLimit, ErrTooManyRequests.Type)
		assert.Equal(t, CodeRateLimit, ErrTooManyRequests.Code)
	})
}

func TestIsAndAs(t *testing.T) {
	t.Run("Is function", func(t *testing.T) {
		err1 := errors.New("test error")
		err2 := fmt.Errorf("wrapped: %w", err1)
		
		assert.True(t, Is(err2, err1))
		assert.False(t, Is(err1, errors.New("different error")))
	})

	t.Run("As function", func(t *testing.T) {
		appErr := New(ErrorTypeValidation, CodeInvalidInput, "test")
		wrapped := fmt.Errorf("wrapped: %w", appErr)
		
		var target *AppError
		assert.True(t, As(wrapped, &target))
		assert.Equal(t, appErr, target)
	})
}

func TestExternalError(t *testing.T) {
	t.Run("ExternalError wraps service errors", func(t *testing.T) {
		original := errors.New("service unavailable")
		err := ExternalError("payment-service", original)
		
		assert.Equal(t, ErrorTypeExternal, err.Type)
		assert.Equal(t, CodeExternalService, err.Code)
		assert.Equal(t, "external service payment-service failed", err.Message)
		assert.Equal(t, original, err.Cause)
	})
}

func TestStackTraceCapture(t *testing.T) {
	t.Run("Stack trace contains function names", func(t *testing.T) {
		err := New(ErrorTypeInternal, CodeInternal, "test")
		
		assert.NotEmpty(t, err.StackTrace)
		assert.Contains(t, err.StackTrace, "TestStackTraceCapture")
		assert.Contains(t, err.StackTrace, "errors_test.go")
	})
}

// Benchmark tests for performance
func BenchmarkErrorCreation(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = New(ErrorTypeValidation, CodeInvalidInput, "test message")
	}
}

func BenchmarkErrorWithStackTrace(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = New(ErrorTypeInternal, CodeInternal, "test").WithStackTrace()
	}
}

func BenchmarkErrorChaining(b *testing.B) {
	for i := 0; i < b.N; i++ {
		original := errors.New("original")
		_ = Wrap(original, ErrorTypeInternal, CodeInternal, "wrapped")
	}
}