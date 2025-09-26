# Domain Layer

This directory contains the core business logic of the n8n-pro application, following Clean Architecture and Domain-Driven Design (DDD) principles.

## Structure

```
domain/
├── README.md                    # This file
├── common/                      # Shared domain concepts
│   ├── errors/                  # Domain-specific errors
│   ├── events/                  # Domain events
│   ├── value_objects/           # Shared value objects
│   └── interfaces/              # Core interfaces
├── user/                        # User aggregate
│   ├── entity.go               # User entity with business logic
│   ├── repository.go           # Repository interface
│   ├── service.go              # Domain service
│   └── value_objects.go        # User-specific value objects
├── workflow/                    # Workflow aggregate
│   ├── entity.go               # Workflow entity
│   ├── repository.go           # Repository interface
│   ├── service.go              # Domain service
│   └── value_objects.go        # Workflow-specific value objects
├── credential/                  # Credential aggregate
├── team/                       # Team aggregate
├── audit/                      # Audit aggregate
└── execution/                  # Execution aggregate
```

## Principles

1. **Independence**: Domain layer should not depend on any external frameworks or infrastructure
2. **Business Logic**: Contains all business rules and domain logic
3. **Entities**: Rich domain objects with behavior, not just data containers
4. **Value Objects**: Immutable objects that represent concepts in your domain
5. **Domain Services**: Services that contain domain logic that doesn't naturally fit within entities
6. **Repository Interfaces**: Defined in domain but implemented in infrastructure layer
7. **Domain Events**: Events that occur within the domain that other parts of the system care about

## Guidelines

- Keep dependencies pointing inward (toward the domain)
- Use interfaces to define contracts with external layers
- Domain entities should contain business logic, not just getters/setters
- Use value objects to represent concepts that don't have identity
- Domain services should only contain logic that doesn't belong in entities
- Use domain events for decoupling between aggregates