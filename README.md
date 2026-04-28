# Endpoint Auth Guard

A security scanner that detects unprotected API endpoints across backend frameworks. Two-layer architecture: fast AST/regex detection + optional LLM analysis via Anthropic API.

Built after a production incident where 70+ FastAPI endpoints were deployed without authentication, exposing user credentials, session tokens, and API keys.

## Supported Frameworks

| Framework | Detection | Auth Patterns |
|-----------|-----------|---------------|
| **FastAPI** | AST | `Depends(get_current_user)`, `APIRouter(dependencies=[...])` |
| **Flask** | AST | `@login_required`, `@roles_required`, `@jwt_required` |
| **Django REST** | AST | `permission_classes`, `@login_required`, `@api_view` |
| **Express.js** | Regex | `passport.authenticate`, `authMiddleware`, `requireAuth` |
| **Spring Boot** | Regex | `@PreAuthorize`, `@Secured`, `@RolesAllowed` |

## Quick Start

```bash
pip install -r requirements.txt

# Scan a project
security-audit scan /path/to/project --format console

# Initialize Claude Code integration in your project
security-audit init
```

## Three Enforcement Points

### 1. Claude Code Hook (dev time)
Blocks `git commit` when staged route files have unprotected HIGH/CRITICAL endpoints. Fail-open on errors — never blocks your workflow.

### 2. GitHub Actions (merge time)
Blocks PR merge and annotates findings inline on the diff.

```yaml
# Add ANTHROPIC_API_KEY secret to your repo for LLM analysis
```

### 3. Slash Command (on demand)
Type `/security-audit` in Claude Code for a full project audit with fix suggestions.

## CLI Usage

```bash
# Console report
security-audit scan . --format console

# JSON report
security-audit scan . --format json

# GitHub Actions annotations
security-audit scan . --format github --exit-code --severity-threshold HIGH

# Scan only staged files
security-audit scan . --git-diff --format console

# Skip LLM layer
security-audit scan . --no-llm --format console

# Set up hook + slash command in current project
security-audit init
```

## Severity Levels

| Severity | Criteria |
|----------|----------|
| **CRITICAL** | Unauthed access to `/admin`, `/users`, `/credentials`, `/sessions`, `/api-keys` |
| **HIGH** | Unauthed state-changing operations (POST/PUT/DELETE/PATCH) on sensitive paths |
| **MEDIUM** | Unauthed read-only access to business data |
| **LOW** | Metadata endpoints |
| **INFO** | Health checks, docs (allowlisted) |

## Configuration

Create `.security-audit.yaml` in your project root:

```yaml
version: 1

allowlist:
  - path: "/health"
    reason: "Load balancer health check"
  - path: "/docs"
    reason: "API documentation"

auth_patterns:
  - "get_current_user"
  - "login_required"
  - "IsAuthenticated"
  - "requireAuth"

severity_rules:
  critical_path_patterns:
    - "/admin"
    - "/users"
    - "/credentials"
  high_path_patterns:
    - "/data"
    - "/export"
    - "/delete"

analysis:
  enabled: true
  model: "claude-sonnet-4-6"
```

## Tests

```bash
python -m pytest tests/ -v
```

## How It Works

**Layer 1 (free, fast):** Python AST parsing for Python frameworks, regex for JS/Java. Finds all route definitions and checks for auth dependencies/decorators/middleware.

**Layer 2 (smart, ~$0.02/file):** Sends flagged files to Claude for deeper analysis — catches non-obvious auth patterns like custom middleware, class-based dependency injection, and indirect auth checks.

## License

MIT
