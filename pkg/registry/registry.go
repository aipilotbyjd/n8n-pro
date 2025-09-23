package registry

import (
	"sync"

	"n8n-pro/pkg/nodes"
	"n8n-pro/pkg/logger"
)

// Registry manages all available node types and their definitions
type Registry struct {
	nodes     map[string]*nodes.NodeDefinition
	factories map[string]nodes.NodeFactory
	mutex     sync.RWMutex
	logger    logger.Logger
}

// New creates a new node registry
func New(log logger.Logger) *Registry {
	return &Registry{
		nodes:     make(map[string]*nodes.NodeDefinition),
		factories: make(map[string]nodes.NodeFactory),
		logger:    log,
	}
}

// Register registers a node type with its definition and factory
func (r *Registry) Register(definition *nodes.NodeDefinition, factory nodes.NodeFactory) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	r.nodes[definition.Name] = definition
	r.factories[definition.Name] = factory
	r.logger.Info("Registered node", "name", definition.Name, "version", definition.Version)
	
	return nil
}

// CreateExecutor creates a new executor instance for a node type
func (r *Registry) CreateExecutor(name string) (nodes.NodeExecutor, error) {
	r.mutex.RLock()
	factory, exists := r.factories[name]
	r.mutex.RUnlock()

	if !exists {
		return nil, nil
	}

	return factory(), nil
}

// GetDefinition returns the definition for a node type
func (r *Registry) GetDefinition(name string) (*nodes.NodeDefinition, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()
	
	if definition, exists := r.nodes[name]; exists {
		return definition, nil
	}
	
	return nil, nil
}