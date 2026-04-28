Scan all Python files in the current project for FastAPI route definitions and check each endpoint for proper authentication dependencies.

Steps:
1. Find all Python files that contain FastAPI route definitions (APIRouter, @router.get/post/etc, @app.get/post/etc)
2. For each endpoint, check if it has proper auth via Depends(get_current_user) or similar patterns
3. List any endpoints missing authentication with their file path, line number, HTTP method, and route path
4. Classify severity: CRITICAL for data/credential access, HIGH for state-changing operations, MEDIUM for read-only business data, LOW for metadata, INFO for health checks
5. For each unprotected endpoint, suggest the specific Depends(...) import and parameter to add
6. Summarize the overall security posture

You can run the scanner directly:
```
python -m src.cli scan . --format console
```

Or for JSON output:
```
python -m src.cli scan . --format json
```

To scan only staged git files:
```
python -m src.cli scan . --git-diff --format console
```
