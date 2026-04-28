Scan all source files in the current project for API route definitions and check each endpoint for proper authentication.

Supported frameworks: FastAPI, Flask, Django REST, Express.js, Spring Boot.

Steps:
1. Find all source files that contain route definitions
2. For each endpoint, check if it has proper auth (decorators, middleware, dependencies)
3. List any endpoints missing authentication with their file path, line number, HTTP method, and route path
4. Classify severity: CRITICAL for data/credential access, HIGH for state-changing operations, MEDIUM for read-only business data, LOW for metadata, INFO for health checks
5. For each unprotected endpoint, suggest the framework-specific fix to add authentication
6. Summarize the overall security posture

You can run the scanner directly:
```
security-audit scan . --format console
```

Or for JSON output:
```
security-audit scan . --format json
```

To scan only staged git files:
```
security-audit scan . --git-diff --format console
```
