package sandbox

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"n8n-pro/pkg/errors"
	"n8n-pro/pkg/logger"
)

// ExecutionContext represents the execution environment
type ExecutionContext string

const (
	ContextJavaScript ExecutionContext = "javascript"
	ContextPython     ExecutionContext = "python"
	ContextShell      ExecutionContext = "shell"
	ContextDocker     ExecutionContext = "docker"
	ContextWASM       ExecutionContext = "wasm"
)

// SecurityLevel defines the sandbox security restrictions
type SecurityLevel string

const (
	SecurityLevelLow    SecurityLevel = "low"
	SecurityLevelMedium SecurityLevel = "medium"
	SecurityLevelHigh   SecurityLevel = "high"
	SecurityLevelStrict SecurityLevel = "strict"
)

// ResourceLimits defines resource constraints for code execution
type ResourceLimits struct {
	MaxCPUTime      time.Duration `json:"max_cpu_time"`
	MaxWallTime     time.Duration `json:"max_wall_time"`
	MaxMemoryMB     int           `json:"max_memory_mb"`
	MaxDiskMB       int           `json:"max_disk_mb"`
	MaxFileSize     int64         `json:"max_file_size"`
	MaxOpenFiles    int           `json:"max_open_files"`
	MaxProcesses    int           `json:"max_processes"`
	MaxNetworkCalls int           `json:"max_network_calls"`
}

// DefaultResourceLimits provides safe default limits
func DefaultResourceLimits() *ResourceLimits {
	return &ResourceLimits{
		MaxCPUTime:      30 * time.Second,
		MaxWallTime:     60 * time.Second,
		MaxMemoryMB:     128,
		MaxDiskMB:       10,
		MaxFileSize:     1024 * 1024, // 1MB
		MaxOpenFiles:    20,
		MaxProcesses:    1,
		MaxNetworkCalls: 10,
	}
}

// Config holds sandbox configuration
type Config struct {
	Context         ExecutionContext  `json:"context"`
	SecurityLevel   SecurityLevel     `json:"security_level"`
	ResourceLimits  *ResourceLimits   `json:"resource_limits"`
	WorkingDir      string            `json:"working_dir"`
	AllowedHosts    []string          `json:"allowed_hosts"`
	AllowedModules  []string          `json:"allowed_modules"`
	ForbiddenApis   []string          `json:"forbidden_apis"`
	EnableLogging   bool              `json:"enable_logging"`
	TrustedDomains  []string          `json:"trusted_domains"`
	EnvironmentVars map[string]string `json:"environment_vars"`
}

// DefaultConfig returns a default sandbox configuration
func DefaultConfig() *Config {
	return &Config{
		Context:         ContextJavaScript,
		SecurityLevel:   SecurityLevelMedium,
		ResourceLimits:  DefaultResourceLimits(),
		WorkingDir:      "/tmp/sandbox",
		AllowedHosts:    []string{"api.example.com"},
		AllowedModules:  []string{"axios", "lodash", "moment"},
		ForbiddenApis:   []string{"eval", "Function", "require", "import"},
		EnableLogging:   true,
		TrustedDomains:  []string{},
		EnvironmentVars: make(map[string]string),
	}
}

// ExecutionResult contains the results of code execution
type ExecutionResult struct {
	Success      bool          `json:"success"`
	Output       string        `json:"output"`
	Error        string        `json:"error,omitempty"`
	ExitCode     int           `json:"exit_code"`
	Duration     time.Duration `json:"duration"`
	MemoryUsed   int64         `json:"memory_used"`
	CPUTime      time.Duration `json:"cpu_time"`
	ReturnValue  interface{}   `json:"return_value,omitempty"`
	Logs         []string      `json:"logs,omitempty"`
	NetworkCalls int           `json:"network_calls"`
	FileAccess   []string      `json:"file_access,omitempty"`
	Warnings     []string      `json:"warnings,omitempty"`
}

// Sandbox provides secure code execution
type Sandbox struct {
	config  *Config
	logger  logger.Logger
	workDir string
}

// New creates a new sandbox instance
func New(config *Config) (*Sandbox, error) {
	if config == nil {
		config = DefaultConfig()
	}

	logger := logger.New("sandbox")

	// Create working directory
	workDir := config.WorkingDir
	if workDir == "" {
		workDir = "/tmp/n8n-sandbox"
	}

	if err := os.MkdirAll(workDir, 0755); err != nil {
		return nil, errors.Wrap(err, errors.ErrorTypeConfiguration, errors.CodeInternal,
			"failed to create sandbox working directory")
	}

	return &Sandbox{
		config:  config,
		logger:  logger,
		workDir: workDir,
	}, nil
}

// Execute runs code in the sandbox
func (s *Sandbox) Execute(ctx context.Context, code string, inputs map[string]interface{}) (*ExecutionResult, error) {
	startTime := time.Now()

	// Validate inputs
	if err := s.validateInputs(code, inputs); err != nil {
		return nil, err
	}

	// Create execution environment
	sandboxExecCtx, err := s.createExecutionContext(ctx, code, inputs)
	if err != nil {
		return nil, err
	}
	defer s.cleanupExecutionContext(sandboxExecCtx)

	// Execute based on context type
	var result *ExecutionResult
	switch s.config.Context {
	case ContextJavaScript:
		result, err = s.executeJavaScript(sandboxExecCtx, code, inputs)
	case ContextPython:
		result, err = s.executePython(sandboxExecCtx, code, inputs)
	case ContextShell:
		result, err = s.executeShell(sandboxExecCtx, code, inputs)
	case ContextDocker:
		result, err = s.executeDocker(sandboxExecCtx, code, inputs)
	case ContextWASM:
		result, err = s.executeWASM(sandboxExecCtx, code, inputs)
	default:
		return nil, errors.New(errors.ErrorTypeValidation, errors.CodeInvalidInput,
			fmt.Sprintf("unsupported execution context: %s", s.config.Context))
	}

	if result != nil {
		result.Duration = time.Since(startTime)
	}

	return result, err
}

// validateInputs validates the code and inputs
func (s *Sandbox) validateInputs(code string, inputs map[string]interface{}) error {
	if strings.TrimSpace(code) == "" {
		return errors.New(errors.ErrorTypeValidation, errors.CodeInvalidInput, "code cannot be empty")
	}

	// Check for forbidden APIs
	for _, forbidden := range s.config.ForbiddenApis {
		if strings.Contains(code, forbidden) {
			return errors.New(errors.ErrorTypeValidation, errors.CodeInvalidInput,
				fmt.Sprintf("forbidden API detected: %s", forbidden))
		}
	}

	// Validate input size
	inputsJSON, _ := json.Marshal(inputs)
	if len(inputsJSON) > 1024*1024 { // 1MB limit
		return errors.New(errors.ErrorTypeValidation, errors.CodeValueOutOfRange,
			"input data too large")
	}

	return nil
}

// ExecutionContext holds context for a single execution
type SandboxExecutionContext struct {
	ID         string
	WorkDir    string
	ScriptPath string
	InputPath  string	OutputPath string
	LogPath    string
	Cancel     context.CancelFunc
	Cmd        *exec.Cmd
	StartTime  time.Time
}

// createExecutionContext sets up the execution environment
func (s *Sandbox) createExecutionContext(ctx context.Context, code string, inputs map[string]interface{}) (*SandboxExecutionContext, error) {
	id := fmt.Sprintf("exec_%d", time.Now().UnixNano())
	execDir := filepath.Join(s.workDir, id)

	if err := os.MkdirAll(execDir, 0755); err != nil {
		return nil, errors.Wrap(err, errors.ErrorTypeInternal, errors.CodeInternal,
			"failed to create execution directory")
	}

	// Create execution context with timeout
	execCtx, cancel := context.WithTimeout(ctx, s.config.ResourceLimits.MaxWallTime)

	sandboxExecCtx := &SandboxExecutionContext{
		ID:         id,
		WorkDir:    execDir,
		ScriptPath: filepath.Join(execDir, "script"),
		InputPath:  filepath.Join(execDir, "input.json"),
		OutputPath: filepath.Join(execDir, "output.json"),
		LogPath:    filepath.Join(execDir, "execution.log"),
		Cancel:     cancel,
		StartTime:  time.Now(),
	}

	// Write input data
	if inputs != nil {
		inputData, err := json.Marshal(inputs)
		if err != nil {
			cancel()
			return nil, errors.Wrap(err, errors.ErrorTypeInternal, errors.CodeInternal,
				"failed to marshal input data")
		}

		if err := os.WriteFile(sandboxExecCtx.InputPath, inputData, 0644); err != nil {
			cancel()
			return nil, errors.Wrap(err, errors.ErrorTypeInternal, errors.CodeInternal,
				"failed to write input data")
		}
	}

	return sandboxExecCtx, nil
}

// cleanupExecutionContext cleans up the execution environment
func (s *Sandbox) cleanupExecutionContext(ctx *SandboxExecutionContext) {
	if ctx == nil {
		return
	}

	ctx.Cancel()

	// Kill any running processes
	if ctx.Cmd != nil && ctx.Cmd.Process != nil {
		ctx.Cmd.Process.Kill()
	}

	// Remove working directory
	os.RemoveAll(ctx.WorkDir)
}

// executeJavaScript runs JavaScript code in a sandboxed Node.js environment
func (s *Sandbox) executeJavaScript(ctx *SandboxExecutionContext, code string, inputs map[string]interface{}) (*ExecutionResult, error) {
	// Wrap the user code with sandbox utilities
	wrappedCode := s.wrapJavaScriptCode(code, ctx.InputPath, ctx.OutputPath)

	// Write the script
	scriptFile := ctx.ScriptPath + ".js"
	if err := os.WriteFile(scriptFile, []byte(wrappedCode), 0644); err != nil {
		return nil, errors.Wrap(err, errors.ErrorTypeInternal, errors.CodeInternal,
			"failed to write JavaScript script")
	}

	// Prepare Node.js command
	cmd := exec.CommandContext(context.Background(), "node", scriptFile)
	cmd.Dir = ctx.WorkDir
	cmd.Env = s.buildEnvironment()

	// Apply resource limits
	s.applyResourceLimits(cmd)

	ctx.Cmd = cmd
	return s.runCommand(ctx, cmd)
}

// wrapJavaScriptCode wraps user code with sandbox utilities
func (s *Sandbox) wrapJavaScriptCode(userCode, inputPath, outputPath string) string {
	return fmt.Sprintf(`
const fs = require('fs');
const path = require('path');

// Sandbox utilities
const sandbox = {
	inputs: {},
	outputs: {},
	log: (...args) => console.log(...args),
	error: (...args) => console.error(...args)
};

// Load inputs
try {
	if (fs.existsSync('%s')) {
		sandbox.inputs = JSON.parse(fs.readFileSync('%s', 'utf8'));
	}
} catch (e) {
	console.error('Failed to load inputs:', e.message);
}

// User code execution
(async function() {
	try {
		%s
	} catch (error) {
		console.error('Execution error:', error.message);
		process.exit(1);
	}
})();

// Save outputs
process.on('exit', () => {
	try {
		fs.writeFileSync('%s', JSON.stringify(sandbox.outputs, null, 2));
	} catch (e) {
		console.error('Failed to save outputs:', e.message);
	}
});
`, inputPath, inputPath, userCode, outputPath)
}

// executePython runs Python code in a sandboxed environment
func (s *Sandbox) executePython(ctx *SandboxExecutionContext, code string, inputs map[string]interface{}) (*ExecutionResult, error) {
	wrappedCode := s.wrapPythonCode(code, ctx.InputPath, ctx.OutputPath)

	scriptFile := ctx.ScriptPath + ".py"
	if err := os.WriteFile(scriptFile, []byte(wrappedCode), 0644); err != nil {
		return nil, errors.Wrap(err, errors.ErrorTypeInternal, errors.CodeInternal,
			"failed to write Python script")
	}

	cmd := exec.CommandContext(context.Background(), "python3", scriptFile)
	cmd.Dir = ctx.WorkDir
	cmd.Env = s.buildEnvironment()

	s.applyResourceLimits(cmd)

	ctx.Cmd = cmd
	return s.runCommand(ctx, cmd)
}

// wrapPythonCode wraps user code with sandbox utilities
func (s *Sandbox) wrapPythonCode(userCode, inputPath, outputPath string) string {
	return fmt.Sprintf(`
import json
import sys
import os

# Sandbox utilities
class Sandbox:
	def __init__(self):
		self.inputs = {}
		self.outputs = {}
		self.load_inputs()

	def load_inputs(self):
		try:
			if os.path.exists('%s'):
				with open('%s', 'r') as f:
					self.inputs = json.load(f)
		except Exception as e:
			print(f"Failed to load inputs: {e}", file=sys.stderr)

	def save_outputs(self):
		try:
			with open('%s', 'w') as f:
				json.dump(self.outputs, f, indent=2)
		except Exception as e:
			print(f"Failed to save outputs: {e}", file=sys.stderr)

	def log(self, *args):
		print(*args)

	def error(self, *args):
		print(*args, file=sys.stderr)

sandbox = Sandbox()

# User code execution
try:
	%s
except Exception as error:
	print(f"Execution error: {error}", file=sys.stderr)
	sys.exit(1)

# Save outputs on exit
sandbox.save_outputs()
`, inputPath, inputPath, outputPath, userCode)
}

// executeShell runs shell commands in a restricted environment
func (s *Sandbox) executeShell(ctx *SandboxExecutionContext, code string, inputs map[string]interface{}) (*ExecutionResult, error) {
	scriptFile := ctx.ScriptPath + ".sh"
	if err := os.WriteFile(scriptFile, []byte(code), 0755); err != nil {
		return nil, errors.Wrap(err, errors.ErrorTypeInternal, errors.CodeInternal,
			"failed to write shell script")
	}

	cmd := exec.CommandContext(context.Background(), "/bin/bash", scriptFile)
	cmd.Dir = ctx.WorkDir
	cmd.Env = s.buildEnvironment()

	s.applyResourceLimits(cmd)

	ctx.Cmd = cmd
	return s.runCommand(ctx, cmd)
}

// executeDocker runs code in a Docker container
func (s *Sandbox) executeDocker(ctx *SandboxExecutionContext, code string, inputs map[string]interface{}) (*ExecutionResult, error) {
	// Create Dockerfile and script
	dockerfile := `FROM node:alpine
WORKDIR /app
COPY script.js .
RUN addgroup -g 1000 sandbox && adduser -D -s /bin/sh -u 1000 -G sandbox sandbox
USER sandbox
CMD ["node", "script.js"]`

	if err := os.WriteFile(filepath.Join(ctx.WorkDir, "Dockerfile"), []byte(dockerfile), 0644); err != nil {
		return nil, errors.Wrap(err, errors.ErrorTypeInternal, errors.CodeInternal,
			"failed to write Dockerfile")
	}

	wrappedCode := s.wrapJavaScriptCode(code, "/app/input.json", "/app/output.json")
	if err := os.WriteFile(filepath.Join(ctx.WorkDir, "script.js"), []byte(wrappedCode), 0644); err != nil {
		return nil, errors.Wrap(err, errors.ErrorTypeInternal, errors.CodeInternal,
			"failed to write script")
	}

	// Build and run Docker container
	buildCmd := exec.CommandContext(context.Background(), "docker", "build", "-t", ctx.ID, ".")
	buildCmd.Dir = ctx.WorkDir
	if err := buildCmd.Run(); err != nil {
		return nil, errors.Wrap(err, errors.ErrorTypeExternal, errors.CodeExternalService,
			"failed to build Docker image")
	}

	runCmd := exec.CommandContext(context.Background(), "docker", "run", "--rm",
		"--memory", fmt.Sprintf("%dm", s.config.ResourceLimits.MaxMemoryMB),
		"--cpus", "0.5",
		"--network", "none",
		ctx.ID)
	runCmd.Dir = ctx.WorkDir

	ctx.Cmd = runCmd
	result, err := s.runCommand(ctx, runCmd)

	// Cleanup Docker image
	cleanupCmd := exec.CommandContext(context.Background(), "docker", "rmi", ctx.ID)
	cleanupCmd.Run()

	return result, err
}

// executeWASM runs WebAssembly code (placeholder implementation)
func (s *Sandbox) executeWASM(ctx *SandboxExecutionContext, code string, inputs map[string]interface{}) (*ExecutionResult, error) {
	return nil, errors.New(errors.ErrorTypeConfiguration, errors.CodeInvalidInput,
		"WASM execution not implemented")
}

// runCommand executes a command and captures the result
func (s *Sandbox) runCommand(ctx *SandboxExecutionContext, cmd *exec.Cmd) (*ExecutionResult, error) {
	result := &ExecutionResult{
		Success: false,
	}

	// Capture output
	output, err := cmd.CombinedOutput()
	result.Output = string(output)

	if err != nil {
		result.Error = err.Error()
		if exitError, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitError.ExitCode()
		}
	} else {
		result.Success = true
	}

	// Try to read output file
	if outputData, err := os.ReadFile(ctx.OutputPath); err == nil {
		var outputs map[string]interface{}
		if err := json.Unmarshal(outputData, &outputs); err == nil {
			result.ReturnValue = outputs
		}
	}

	// Read logs if available
	if logData, err := os.ReadFile(ctx.LogPath); err == nil {
		result.Logs = strings.Split(string(logData), "\n")
	}

	return result, nil
}

// applyResourceLimits applies resource constraints to the command
func (s *Sandbox) applyResourceLimits(cmd *exec.Cmd) {
	limits := s.config.ResourceLimits

	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}

	// Apply memory limit (if supported)
	// Note: This is a simplified implementation
	// In production, you'd use cgroups or similar mechanisms
}

// buildEnvironment creates a restricted environment
func (s *Sandbox) buildEnvironment() []string {
	env := []string{
		"PATH=/usr/local/bin:/usr/bin:/bin",
		"HOME=" + s.workDir,
		"USER=sandbox",
		"SHELL=/bin/sh",
	}

	// Add custom environment variables
	for key, value := range s.config.EnvironmentVars {
		env = append(env, fmt.Sprintf("%s=%s", key, value))
	}

	return env
}

// ValidateCode performs static analysis on code before execution
func (s *Sandbox) ValidateCode(code string) error {
	// Check for dangerous patterns
	dangerousPatterns := []string{
		"require('child_process')",
		"require('fs')",
		"process.exit",
		"eval(",
		"Function(",
		"import(",
		"__dirname",
		"__filename",
	}

	if s.config.SecurityLevel == SecurityLevelStrict {
		for _, pattern := range dangerousPatterns {
			if strings.Contains(code, pattern) {
				return errors.New(errors.ErrorTypeValidation, errors.CodeInvalidInput,
					fmt.Sprintf("dangerous pattern detected: %s", pattern))
			}
		}
	}

	return nil
}

// GetExecutionStats returns statistics about sandbox usage
func (s *Sandbox) GetExecutionStats() map[string]interface{} {
	return map[string]interface{}{
		"working_directory": s.workDir,
		"security_level":    s.config.SecurityLevel,
		"execution_context": s.config.Context,
		"resource_limits":   s.config.ResourceLimits,
	}
}

// Close cleans up sandbox resources
func (s *Sandbox) Close() error {
	return os.RemoveAll(s.workDir)
}
