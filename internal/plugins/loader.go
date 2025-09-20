package plugins

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"n8n-pro/internal/nodes"
	"n8n-pro/pkg/errors"
	"n8n-pro/pkg/logger"
)

// PluginType represents different types of plugins
type PluginType string

const (
	PluginTypeNode        PluginType = "node"
	PluginTypeCredential  PluginType = "credential"
	PluginTypeTrigger     PluginType = "trigger"
	PluginTypeMiddleware  PluginType = "middleware"
	PluginTypeTransform   PluginType = "transform"
	PluginTypeConnector   PluginType = "connector"
	PluginTypeExtension   PluginType = "extension"
	PluginTypeIntegration PluginType = "integration"
)

// PluginStatus represents the current status of a plugin
type PluginStatus string

const (
	PluginStatusInstalled PluginStatus = "installed"
	PluginStatusEnabled   PluginStatus = "enabled"
	PluginStatusDisabled  PluginStatus = "disabled"
	PluginStatusLoading   PluginStatus = "loading"
	PluginStatusError     PluginStatus = "error"
	PluginStatusUpdating  PluginStatus = "updating"
)

// PluginManifest represents plugin metadata
type PluginManifest struct {
	Name         string            `json:"name"`
	DisplayName  string            `json:"displayName"`
	Description  string            `json:"description"`
	Version      string            `json:"version"`
	Author       string            `json:"author"`
	License      string            `json:"license"`
	Homepage     string            `json:"homepage,omitempty"`
	Repository   string            `json:"repository,omitempty"`
	Keywords     []string          `json:"keywords,omitempty"`
	Type         PluginType        `json:"type"`
	Category     string            `json:"category,omitempty"`
	Icon         string            `json:"icon,omitempty"`
	Main         string            `json:"main"`
	Dependencies []string          `json:"dependencies,omitempty"`
	PeerDeps     []string          `json:"peerDependencies,omitempty"`
	MinVersion   string            `json:"minVersion,omitempty"`
	MaxVersion   string            `json:"maxVersion,omitempty"`
	Permissions  []string          `json:"permissions,omitempty"`
	Config       PluginConfig      `json:"config,omitempty"`
	Nodes        []string          `json:"nodes,omitempty"`
	Credentials  []string          `json:"credentials,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

// PluginConfig represents plugin configuration schema
type PluginConfig struct {
	Properties map[string]ConfigProperty `json:"properties,omitempty"`
	Required   []string                  `json:"required,omitempty"`
}

// ConfigProperty represents a configuration property
type ConfigProperty struct {
	Type        string      `json:"type"`
	Description string      `json:"description,omitempty"`
	Default     interface{} `json:"default,omitempty"`
	Options     []string    `json:"options,omitempty"`
	Min         *int        `json:"min,omitempty"`
	Max         *int        `json:"max,omitempty"`
	Pattern     string      `json:"pattern,omitempty"`
	Format      string      `json:"format,omitempty"`
}

// Plugin represents a loaded plugin
type Plugin struct {
	ID        string                 `json:"id"`
	Manifest  *PluginManifest        `json:"manifest"`
	Status    PluginStatus           `json:"status"`
	Path      string                 `json:"path"`
	Instance  PluginInstance         `json:"-"`
	Config    map[string]interface{} `json:"config,omitempty"`
	LoadedAt  time.Time              `json:"loaded_at"`
	UpdatedAt time.Time              `json:"updated_at"`
	Error     string                 `json:"error,omitempty"`
	Checksum  string                 `json:"checksum,omitempty"`
	Size      int64                  `json:"size"`
}

// PluginInstance defines the interface that all plugins must implement
type PluginInstance interface {
	Initialize(config map[string]interface{}) error
	GetManifest() *PluginManifest
	GetNodes() ([]nodes.NodeExecutor, error)
	GetCredentials() ([]CredentialType, error)
	Validate() error
	Cleanup() error
	GetInfo() map[string]interface{}
}

// CredentialType represents a credential type provided by a plugin
type CredentialType struct {
	Name        string                 `json:"name"`
	DisplayName string                 `json:"displayName"`
	Description string                 `json:"description"`
	Properties  []CredentialProperty   `json:"properties"`
	Icon        string                 `json:"icon,omitempty"`
	TestURL     string                 `json:"testUrl,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// CredentialProperty represents a property of a credential
type CredentialProperty struct {
	Name        string      `json:"name"`
	DisplayName string      `json:"displayName"`
	Type        string      `json:"type"`
	Required    bool        `json:"required"`
	Default     interface{} `json:"default,omitempty"`
	Placeholder string      `json:"placeholder,omitempty"`
	Secret      bool        `json:"secret,omitempty"`
	Options     []string    `json:"options,omitempty"`
}

// LoaderConfig represents plugin loader configuration
type LoaderConfig struct {
	PluginsDir      string        `json:"plugins_dir" yaml:"plugins_dir"`
	EnableHotReload bool          `json:"enable_hot_reload" yaml:"enable_hot_reload"`
	ReloadInterval  time.Duration `json:"reload_interval" yaml:"reload_interval"`
	MaxPlugins      int           `json:"max_plugins" yaml:"max_plugins"`
	EnableSandbox   bool          `json:"enable_sandbox" yaml:"enable_sandbox"`
	AllowedPaths    []string      `json:"allowed_paths" yaml:"allowed_paths"`
	BlockedPaths    []string      `json:"blocked_paths" yaml:"blocked_paths"`
	TrustedSources  []string      `json:"trusted_sources" yaml:"trusted_sources"`
	EnableMetrics   bool          `json:"enable_metrics" yaml:"enable_metrics"`
	CacheEnabled    bool          `json:"cache_enabled" yaml:"cache_enabled"`
	CacheTTL        time.Duration `json:"cache_ttl" yaml:"cache_ttl"`
	SecurityChecks  bool          `json:"security_checks" yaml:"security_checks"`
	AutoUpdate      bool          `json:"auto_update" yaml:"auto_update"`
	BackupOnUpdate  bool          `json:"backup_on_update" yaml:"backup_on_update"`
}

// DefaultLoaderConfig returns default loader configuration
func DefaultLoaderConfig() *LoaderConfig {
	return &LoaderConfig{
		PluginsDir:      "./plugins",
		EnableHotReload: false,
		ReloadInterval:  30 * time.Second,
		MaxPlugins:      100,
		EnableSandbox:   true,
		AllowedPaths:    []string{"./plugins", "./data/plugins"},
		BlockedPaths:    []string{"/etc", "/usr", "/bin", "/sbin"},
		TrustedSources:  []string{"github.com/n8n-io"},
		EnableMetrics:   true,
		CacheEnabled:    true,
		CacheTTL:        1 * time.Hour,
		SecurityChecks:  true,
		AutoUpdate:      false,
		BackupOnUpdate:  true,
	}
}

// Registry manages plugin registration and discovery
type Registry struct {
	plugins    map[string]*Plugin
	byType     map[PluginType][]*Plugin
	byCategory map[string][]*Plugin
	nodeReg    *nodes.Registry
	mutex      sync.RWMutex
}

// NewRegistry creates a new plugin registry
func NewRegistry(nodeRegistry *nodes.Registry) *Registry {
	return &Registry{
		plugins:    make(map[string]*Plugin),
		byType:     make(map[PluginType][]*Plugin),
		byCategory: make(map[string][]*Plugin),
		nodeReg:    nodeRegistry,
	}
}

// Loader manages plugin loading and lifecycle
type Loader struct {
	config        *LoaderConfig
	registry      *Registry
	logger        logger.Logger
	watcher       *FileWatcher
	ctx           context.Context
	cancel        context.CancelFunc
	wg            sync.WaitGroup
	metrics       LoaderMetrics
	cache         map[string]*Plugin
	cacheMutex    sync.RWMutex
	eventHandlers map[string][]EventHandler
	handlersMutex sync.RWMutex
}

// LoaderMetrics represents loader metrics
type LoaderMetrics struct {
	PluginsLoaded   int64 `json:"plugins_loaded"`
	PluginsFailed   int64 `json:"plugins_failed"`
	PluginsEnabled  int64 `json:"plugins_enabled"`
	PluginsDisabled int64 `json:"plugins_disabled"`
	NodesRegistered int64 `json:"nodes_registered"`
	ReloadCount     int64 `json:"reload_count"`
	LastReloadAt    int64 `json:"last_reload_at"`
}

// EventHandler defines plugin event handler interface
type EventHandler func(event *PluginEvent)

// PluginEvent represents a plugin lifecycle event
type PluginEvent struct {
	Type      string                 `json:"type"`
	PluginID  string                 `json:"plugin_id"`
	Plugin    *Plugin                `json:"plugin,omitempty"`
	Data      map[string]interface{} `json:"data,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
}

// FileWatcher watches for plugin file changes
type FileWatcher struct {
	paths     []string
	callbacks []func(string)
	ticker    *time.Ticker
	ctx       context.Context
	cancel    context.CancelFunc
	logger    logger.Logger
}

// NewLoader creates a new plugin loader
func NewLoader(config *LoaderConfig, nodeRegistry *nodes.Registry, log logger.Logger) *Loader {
	if config == nil {
		config = DefaultLoaderConfig()
	}

	ctx, cancel := context.WithCancel(context.Background())
	registry := NewRegistry(nodeRegistry)

	loader := &Loader{
		config:        config,
		registry:      registry,
		logger:        log,
		ctx:           ctx,
		cancel:        cancel,
		cache:         make(map[string]*Plugin),
		eventHandlers: make(map[string][]EventHandler),
	}

	// Initialize file watcher if hot reload is enabled
	if config.EnableHotReload {
		loader.watcher = NewFileWatcher([]string{config.PluginsDir}, log)
		loader.watcher.OnChange(loader.handleFileChange)
	}

	return loader
}

// Start starts the plugin loader
func (l *Loader) Start() error {
	l.logger.Info("Starting plugin loader", "plugins_dir", l.config.PluginsDir)

	// Create plugins directory if it doesn't exist
	if err := os.MkdirAll(l.config.PluginsDir, 0755); err != nil {
		return fmt.Errorf("failed to create plugins directory: %w", err)
	}

	// Load existing plugins
	if err := l.LoadPlugins(); err != nil {
		l.logger.Error("Failed to load plugins during startup", "error", err)
		return err
	}

	// Start file watcher if enabled
	if l.watcher != nil {
		l.wg.Add(1)
		go func() {
			defer l.wg.Done()
			l.watcher.Start()
		}()
	}

	l.logger.Info("Plugin loader started", "plugins_loaded", len(l.registry.plugins))
	return nil
}

// Stop stops the plugin loader
func (l *Loader) Stop() error {
	l.logger.Info("Stopping plugin loader...")

	// Cancel context
	l.cancel()

	// Stop file watcher
	if l.watcher != nil {
		l.watcher.Stop()
	}

	// Wait for goroutines to finish
	l.wg.Wait()

	// Cleanup all plugins
	l.registry.mutex.Lock()
	defer l.registry.mutex.Unlock()

	for _, plugin := range l.registry.plugins {
		if plugin.Instance != nil {
			plugin.Instance.Cleanup()
		}
	}

	l.logger.Info("Plugin loader stopped")
	return nil
}

// LoadPlugins scans and loads all plugins from the plugins directory
func (l *Loader) LoadPlugins() error {
	l.logger.Info("Loading plugins from directory", "dir", l.config.PluginsDir)

	err := filepath.WalkDir(l.config.PluginsDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Skip non-directories
		if !d.IsDir() {
			return nil
		}

		// Skip root directory
		if path == l.config.PluginsDir {
			return nil
		}

		// Check for plugin manifest
		manifestPath := filepath.Join(path, "plugin.json")
		if _, err := os.Stat(manifestPath); os.IsNotExist(err) {
			return nil // Not a plugin directory
		}

		// Load plugin
		if err := l.LoadPlugin(path); err != nil {
			l.logger.Error("Failed to load plugin", "path", path, "error", err)
			l.metrics.PluginsFailed++
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("failed to scan plugins directory: %w", err)
	}

	l.logger.Info("Finished loading plugins", "loaded", l.metrics.PluginsLoaded, "failed", l.metrics.PluginsFailed)
	return nil
}

// LoadPlugin loads a single plugin from the specified path
func (l *Loader) LoadPlugin(pluginPath string) error {
	// Read manifest
	manifestPath := filepath.Join(pluginPath, "plugin.json")
	manifestData, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("failed to read plugin manifest: %w", err)
	}

	var manifest PluginManifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return fmt.Errorf("failed to parse plugin manifest: %w", err)
	}

	// Validate manifest
	if err := l.validateManifest(&manifest); err != nil {
		return fmt.Errorf("invalid plugin manifest: %w", err)
	}

	// Check if plugin already exists
	pluginID := manifest.Name
	l.registry.mutex.RLock()
	existingPlugin, exists := l.registry.plugins[pluginID]
	l.registry.mutex.RUnlock()

	if exists {
		// Check version for updates
		if existingPlugin.Manifest.Version == manifest.Version {
			l.logger.Debug("Plugin already loaded with same version", "plugin", pluginID)
			return nil
		}
		l.logger.Info("Updating plugin", "plugin", pluginID, "old_version", existingPlugin.Manifest.Version, "new_version", manifest.Version)
	}

	l.logger.Info("Loading plugin", "plugin", pluginID, "version", manifest.Version, "path", pluginPath)

	// Create plugin instance
	plugin := &Plugin{
		ID:        pluginID,
		Manifest:  &manifest,
		Status:    PluginStatusLoading,
		Path:      pluginPath,
		LoadedAt:  time.Now(),
		UpdatedAt: time.Now(),
	}

	// Load plugin binary/script
	if err := l.loadPluginInstance(plugin); err != nil {
		plugin.Status = PluginStatusError
		plugin.Error = err.Error()
		l.logger.Error("Failed to load plugin instance", "plugin", pluginID, "error", err)
		return err
	}

	// Initialize plugin
	if err := plugin.Instance.Initialize(plugin.Config); err != nil {
		plugin.Status = PluginStatusError
		plugin.Error = err.Error()
		return fmt.Errorf("failed to initialize plugin: %w", err)
	}

	// Register plugin nodes
	if err := l.registerPluginNodes(plugin); err != nil {
		l.logger.Error("Failed to register plugin nodes", "plugin", pluginID, "error", err)
		// Don't fail the entire plugin load for node registration failures
	}

	// Update status and register
	plugin.Status = PluginStatusEnabled
	l.registerPlugin(plugin)

	// Emit loaded event
	l.emitEvent(&PluginEvent{
		Type:      "plugin_loaded",
		PluginID:  pluginID,
		Plugin:    plugin,
		Timestamp: time.Now(),
	})

	l.metrics.PluginsLoaded++
	l.logger.Info("Plugin loaded successfully", "plugin", pluginID, "version", manifest.Version)

	return nil
}

// UnloadPlugin unloads a plugin
func (l *Loader) UnloadPlugin(pluginID string) error {
	l.registry.mutex.Lock()
	defer l.registry.mutex.Unlock()

	plugin, exists := l.registry.plugins[pluginID]
	if !exists {
		return errors.NewNotFoundError(fmt.Sprintf("plugin '%s' not found", pluginID))
	}

	l.logger.Info("Unloading plugin", "plugin", pluginID)

	// Cleanup plugin instance
	if plugin.Instance != nil {
		if err := plugin.Instance.Cleanup(); err != nil {
			l.logger.Error("Error during plugin cleanup", "plugin", pluginID, "error", err)
		}
	}

	// Unregister nodes
	l.unregisterPluginNodes(plugin)

	// Remove from registry
	delete(l.registry.plugins, pluginID)

	// Remove from type and category indices
	l.removeFromIndices(plugin)

	// Emit unloaded event
	l.emitEvent(&PluginEvent{
		Type:      "plugin_unloaded",
		PluginID:  pluginID,
		Timestamp: time.Now(),
	})

	l.logger.Info("Plugin unloaded successfully", "plugin", pluginID)
	return nil
}

// GetPlugin retrieves a plugin by ID
func (l *Loader) GetPlugin(pluginID string) (*Plugin, error) {
	l.registry.mutex.RLock()
	defer l.registry.mutex.RUnlock()

	plugin, exists := l.registry.plugins[pluginID]
	if !exists {
		return nil, errors.NewNotFoundError(fmt.Sprintf("plugin '%s' not found", pluginID))
	}

	return plugin, nil
}

// ListPlugins returns all loaded plugins
func (l *Loader) ListPlugins() []*Plugin {
	l.registry.mutex.RLock()
	defer l.registry.mutex.RUnlock()

	var plugins []*Plugin
	for _, plugin := range l.registry.plugins {
		plugins = append(plugins, plugin)
	}

	return plugins
}

// GetPluginsByType returns plugins of a specific type
func (l *Loader) GetPluginsByType(pluginType PluginType) []*Plugin {
	l.registry.mutex.RLock()
	defer l.registry.mutex.RUnlock()

	return l.registry.byType[pluginType]
}

// EnablePlugin enables a disabled plugin
func (l *Loader) EnablePlugin(pluginID string) error {
	l.registry.mutex.Lock()
	defer l.registry.mutex.Unlock()

	plugin, exists := l.registry.plugins[pluginID]
	if !exists {
		return errors.NewNotFoundError(fmt.Sprintf("plugin '%s' not found", pluginID))
	}

	if plugin.Status == PluginStatusEnabled {
		return nil // Already enabled
	}

	l.logger.Info("Enabling plugin", "plugin", pluginID)

	// Re-register nodes
	if err := l.registerPluginNodes(plugin); err != nil {
		return fmt.Errorf("failed to register plugin nodes: %w", err)
	}

	plugin.Status = PluginStatusEnabled
	plugin.UpdatedAt = time.Now()
	l.metrics.PluginsEnabled++

	// Emit enabled event
	l.emitEvent(&PluginEvent{
		Type:      "plugin_enabled",
		PluginID:  pluginID,
		Plugin:    plugin,
		Timestamp: time.Now(),
	})

	return nil
}

// DisablePlugin disables an enabled plugin
func (l *Loader) DisablePlugin(pluginID string) error {
	l.registry.mutex.Lock()
	defer l.registry.mutex.Unlock()

	plugin, exists := l.registry.plugins[pluginID]
	if !exists {
		return errors.NewNotFoundError(fmt.Sprintf("plugin '%s' not found", pluginID))
	}

	if plugin.Status == PluginStatusDisabled {
		return nil // Already disabled
	}

	l.logger.Info("Disabling plugin", "plugin", pluginID)

	// Unregister nodes
	l.unregisterPluginNodes(plugin)

	plugin.Status = PluginStatusDisabled
	plugin.UpdatedAt = time.Now()
	l.metrics.PluginsDisabled++

	// Emit disabled event
	l.emitEvent(&PluginEvent{
		Type:      "plugin_disabled",
		PluginID:  pluginID,
		Plugin:    plugin,
		Timestamp: time.Now(),
	})

	return nil
}

// ReloadPlugin reloads a plugin
func (l *Loader) ReloadPlugin(pluginID string) error {
	plugin, err := l.GetPlugin(pluginID)
	if err != nil {
		return err
	}

	l.logger.Info("Reloading plugin", "plugin", pluginID)

	// Unload first
	if err := l.UnloadPlugin(pluginID); err != nil {
		return fmt.Errorf("failed to unload plugin: %w", err)
	}

	// Reload
	if err := l.LoadPlugin(plugin.Path); err != nil {
		return fmt.Errorf("failed to reload plugin: %w", err)
	}

	l.metrics.ReloadCount++
	l.metrics.LastReloadAt = time.Now().Unix()

	return nil
}

// GetMetrics returns loader metrics
func (l *Loader) GetMetrics() LoaderMetrics {
	return l.metrics
}

// OnEvent registers an event handler
func (l *Loader) OnEvent(eventType string, handler EventHandler) {
	l.handlersMutex.Lock()
	defer l.handlersMutex.Unlock()

	l.eventHandlers[eventType] = append(l.eventHandlers[eventType], handler)
}

// Helper methods

func (l *Loader) validateManifest(manifest *PluginManifest) error {
	if manifest.Name == "" {
		return errors.NewValidationError("plugin name is required")
	}
	if manifest.Version == "" {
		return errors.NewValidationError("plugin version is required")
	}
	if manifest.Main == "" {
		return errors.NewValidationError("plugin main entry point is required")
	}
	if manifest.Type == "" {
		return errors.NewValidationError("plugin type is required")
	}

	return nil
}

func (l *Loader) loadPluginInstance(plugin *Plugin) error {
	mainPath := filepath.Join(plugin.Path, plugin.Manifest.Main)

	// Check if main file exists
	if _, err := os.Stat(mainPath); os.IsNotExist(err) {
		return fmt.Errorf("plugin main file not found: %s", mainPath)
	}

	// For Go plugins, load as shared library
	if strings.HasSuffix(plugin.Manifest.Main, ".so") {
		return l.loadGoPlugin(plugin, mainPath)
	}

	// For other types, we would implement different loaders
	return errors.NewValidationError("unsupported plugin type")
}

func (l *Loader) loadGoPlugin(plugin *Plugin, path string) error {
	// Load Go plugin
	p, err := plugin.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open plugin: %w", err)
	}

	// Look for New function
	newFunc, err := p.Lookup("New")
	if err != nil {
		return fmt.Errorf("plugin missing New function: %w", err)
	}

	// Call New function
	newPluginFunc, ok := newFunc.(func() PluginInstance)
	if !ok {
		return fmt.Errorf("invalid New function signature")
	}

	plugin.Instance = newPluginFunc()
	return nil
}

func (l *Loader) registerPlugin(plugin *Plugin) {
	l.registry.mutex.Lock()
	defer l.registry.mutex.Unlock()

	// Remove existing plugin if it exists
	if existing, exists := l.registry.plugins[plugin.ID]; exists {
		l.removeFromIndices(existing)
	}

	// Add to main registry
	l.registry.plugins[plugin.ID] = plugin

	// Add to type index
	l.registry.byType[plugin.Manifest.Type] = append(l.registry.byType[plugin.Manifest.Type], plugin)

	// Add to category index
	if plugin.Manifest.Category != "" {
		l.registry.byCategory[plugin.Manifest.Category] = append(l.registry.byCategory[plugin.Manifest.Category], plugin)
	}
}

func (l *Loader) removeFromIndices(plugin *Plugin) {
	// Remove from type index
	typePlugins := l.registry.byType[plugin.Manifest.Type]
	for i, p := range typePlugins {
		if p.ID == plugin.ID {
			l.registry.byType[plugin.Manifest.Type] = append(typePlugins[:i], typePlugins[i+1:]...)
			break
		}
	}

	// Remove from category index
	if plugin.Manifest.Category != "" {
		categoryPlugins := l.registry.byCategory[plugin.Manifest.Category]
		for i, p := range categoryPlugins {
			if p.ID == plugin.ID {
				l.registry.byCategory[plugin.Manifest.Category] = append(categoryPlugins[:i], categoryPlugins[i+1:]...)
				break
			}
		}
	}
}

func (l *Loader) registerPluginNodes(plugin *Plugin) error {
	if l.registry.nodeReg == nil || plugin.Instance == nil {
		return nil
	}

	nodeExecutors, err := plugin.Instance.GetNodes()
	if err != nil {
		return err
	}

	for _, executor := range nodeExecutors {
		definition := executor.GetDefinition()
		factory := func() nodes.NodeExecutor { return executor }

		if err := l.registry.nodeReg.Register(definition, factory); err != nil {
			l.logger.Error("Failed to register node from plugin", "node", definition.Name, "plugin", plugin.ID, "error", err)
			continue
		}

		l.metrics.NodesRegistered++
		l.logger.Debug("Registered node from plugin", "node", definition.Name, "plugin", plugin.ID)
	}

	return nil
}

func (l *Loader) unregisterPluginNodes(plugin *Plugin) {
	if l.registry.nodeReg == nil || plugin.Instance == nil {
		return
	}

	nodeExecutors, err := plugin.Instance.GetNodes()
	if err != nil {
		return
	}

	for _, executor := range nodeExecutors {
		definition := executor.GetDefinition()
		if err := l.registry.nodeReg.Unregister(definition.Name); err != nil {
			l.logger.Error("Failed to unregister node from plugin", "node", definition.Name, "plugin", plugin.ID, "error", err)
		}
	}
}

func (l *Loader) emitEvent(event *PluginEvent) {
	l.handlersMutex.RLock()
	defer l.handlersMutex.RUnlock()

	handlers := l.eventHandlers[event.Type]
	for _, handler := range handlers {
		go func(h EventHandler) {
			defer func() {
				if r := recover(); r != nil {
					l.logger.Error("Panic in plugin event handler", "error", r, "event_type", event.Type)
				}
			}()
			h(event)
		}(handler)
	}
}

func (l *Loader) handleFileChange(path string) {
	l.logger.Debug("Plugin file changed, reloading", "path", path)

	// Find plugin by path and reload
	l.registry.mutex.RLock()
	var targetPlugin *Plugin
	for _, plugin := range l.registry.plugins {
		if strings.HasPrefix(path, plugin.Path) {
			targetPlugin = plugin
			break
		}
	}
	l.registry.mutex.RUnlock()

	if targetPlugin != nil {
		if err := l.ReloadPlugin(targetPlugin.ID); err != nil {
			l.logger.Error("Failed to reload plugin after file change", "plugin", targetPlugin.ID, "error", err)
		}
	}
}

// NewFileWatcher creates a new file watcher
func NewFileWatcher(paths []string, log logger.Logger) *FileWatcher {
	ctx, cancel := context.WithCancel(context.Background())
	return &FileWatcher{
		paths:  paths,
		ctx:    ctx,
		cancel: cancel,
		logger: log,
	}
}

// OnChange registers a callback for file changes
func (w *FileWatcher) OnChange(callback func(string)) {
	w.callbacks = append(w.callbacks, callback)
}

// Start starts the file watcher
func (w *FileWatcher) Start() {
	w.ticker = time.NewTicker(5 * time.Second)
	defer w.ticker.Stop()

	lastMods := make(map[string]time.Time)

	for {
		select {
		case <-w.ctx.Done():
			return
		case <-w.ticker.C:
			w.checkChanges(lastMods)
		}
	}
}

// Stop stops the file watcher
func (w *FileWatcher) Stop() {
	if w.cancel != nil {
		w.cancel()
	}
}

func (w *FileWatcher) checkChanges(lastMods map[string]time.Time) {
	for _, watchPath := range w.paths {
		filepath.WalkDir(watchPath, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}

			if d.IsDir() {
				return nil
			}

			info, err := d.Info()
			if err != nil {
				return nil
			}

			lastMod := info.ModTime()
			if oldMod, exists := lastMods[path]; exists && lastMod.After(oldMod) {
				// File has been modified
				for _, callback := range w.callbacks {
					callback(path)
				}
			}

			lastMods[path] = lastMod
			return nil
		})
	}
}
