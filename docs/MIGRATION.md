# Migration to New Project Structure

This document describes the migration from the old project structure to the new Domain-Driven Design (DDD) structure.

## What Changed

### Directory Structure
- **Before**: Flat structure with mixed concerns
- **After**: Layered architecture with clear separation of concerns

### Key Changes
1. **Database**: Consolidated from `internal/db` and `internal/database` to `internal/infrastructure/database`
2. **API**: Moved from `internal/api` to `internal/presentation/http`
3. **Services**: Reorganized from `internal/services` to `internal/application/*`
4. **Domain Logic**: Centralized in `internal/domain/*`
5. **Configuration**: Moved to `configs/` directory
6. **Scripts**: Organized in `scripts/` directory
7. **Binaries**: Output to `build/` directory

## Import Path Updates

Old Path | New Path
---------|----------
`n8n-pro/internal/api` | `n8n-pro/internal/presentation/http`
`n8n-pro/internal/database` | `n8n-pro/internal/infrastructure/database`
`n8n-pro/internal/auth` | `n8n-pro/internal/application/auth`
`n8n-pro/internal/workflows` | `n8n-pro/internal/domain/workflow`
`n8n-pro/internal/common` | `n8n-pro/internal/shared`

## Next Steps
1. Run tests to ensure everything works: `make test`
2. Update your IDE's import settings
3. Review and update any custom scripts
4. Update CI/CD pipelines if necessary
