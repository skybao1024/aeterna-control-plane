# Claude Code Hooks Configuration

This document describes the Claude Code hooks configured in this project for automated code quality checks and formatting.

## Overview

The project uses two types of hooks to maintain code quality:

1. **PreToolUse Hook**: Intelligent code duplication detection before writing files
2. **Stop Hook**: Automated code formatting after Claude completes its response

## Hook Configuration

Configuration file: `.claude/settings.json`

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Edit|Write",
        "hooks": [
          {
            "type": "command",
            "command": "python3 \"$CLAUDE_PROJECT_DIR\"/.claude/hooks/pre-write-intelligent.py",
            "timeout": 10
          }
        ]
      }
    ],
    "Stop": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "python3 \"$CLAUDE_PROJECT_DIR\"/.claude/hooks/format-on-stop.py",
            "timeout": 60
          }
        ]
      }
    ]
  }
}
```

## PreToolUse Hook: Intelligent Code Duplication Detection

**Script**: `.claude/hooks/pre-write-intelligent.py`
**Trigger**: Before `Edit` or `Write` tool execution
**Timeout**: 10 seconds

### Features

#### 1. AST-Based Code Analysis

The hook uses Python's Abstract Syntax Tree (AST) to analyze code structure:

- **Class definitions**: Names, methods, base classes, decorators
- **Function definitions**: Top-level functions and their names
- **Import statements**: Dependencies and external libraries
- **Decorators**: Framework-specific annotations

#### 2. Multi-Dimensional Similarity Scoring

Calculates similarity across multiple dimensions with weighted scoring:

| Dimension | Weight | Description |
|-----------|--------|-------------|
| Class names | 20% | Similarity of class identifiers |
| Method names | 25% | Similarity of method identifiers (highest weight) |
| Imports | 15% | Similarity of dependencies |
| Decorators | 10% | Similarity of annotations |
| Base classes | 15% | Similarity of inheritance relationships |
| Function names | 15% | Similarity of top-level function identifiers |

**Total Score**: 0-100 (weighted sum of all dimensions)

#### 3. Architecture-Aware Thresholds

Different code layers have different similarity thresholds:

| File Role | Threshold | Rationale |
|-----------|-----------|-----------|
| Service layer | 60% | Lower threshold to catch exact copies |
| Model layer | 55% | Catch duplicate data models |
| API layer | 45% | Loose check (endpoints may be similar) |
| Schema layer | 45% | Loose check (DTOs may be similar) |
| Utility layer | 65% | Stricter check for shared utilities |
| Default | 60% | General purpose threshold |

File roles are automatically detected based on file paths:
- `/services/` → Service layer
- `/models/` → Model layer
- `/api/` or `/route/` → API layer
- `/schemas/` → Schema layer
- `/utils/` or `/core/` → Utility layer

#### 4. Intelligent File Search

The hook optimizes search by:

1. **Scoping by architecture layer**: Only compares files within the same layer
2. **Excluding irrelevant files**: Skips virtual environments, migrations, tests, cache
3. **Performance limits**:
   - Maximum file size: 5MB
   - Maximum candidate files: 30
   - Find command timeout: 5 seconds

#### 5. Architecture Rule Validation

Enforces architectural constraints:

**Rule 1: Layer Dependency**
- Core/Common layer cannot import from Service layer
- Violation: `ERROR` severity

**Rule 2: Singleton Pattern**
- Redis instances should only be created in `app/services/common/redis.py`
- Database engines should only be created in `app/db/base.py`
- Violation: `ERROR` severity

**Rule 3: Configuration Access**
- Environment variables should be accessed through `app/core/config.py`
- Direct `os.getenv()` or `os.environ` usage elsewhere: `WARNING` severity

### Behavior

The hook provides different responses based on severity:

#### High Severity (Blocks Write)
- Similarity score ≥ 80%
- Architecture rule violations (ERROR level)
- **Action**: Requests user confirmation with detailed analysis

#### Moderate Severity (Shows Warning)
- Similarity score: 60-79%
- Architecture rule violations (WARNING level)
- **Action**: Displays warning but allows write to proceed

#### Low Severity (Silent Pass)
- Similarity score < 60%
- No rule violations
- **Action**: Allows write without notification

### Output Format

```
🔍 Intelligent Pre-Write Analysis
════════════════════════════════════════════════════════════

📊 Code Similarity Analysis (Role: service)

1. 🚨 Very High Similarity: 85.3/100 (Threshold: 60)
   Similar to: app/services/client/auth_service.py
   Breakdown:
     - class_name: 90%
     - method_names: 85%
     - imports: 80%
     - decorators: 75%

💡 Recommendations:
   1. Review existing code - Can you extend it instead?
   2. If functionality differs, consider renaming for clarity
   3. Consult @architecture-advisor if unsure

🚨 Architecture Rule Violations:

❌ Layer Dependency
   Core/Common layer cannot import from Service layer
   Details: Found imports: client, backoffice
```

### Excluded Files

The following patterns are automatically excluded from checks:

- `/venv/`, `/env/`, `/.venv/` - Virtual environments
- `/__pycache__/` - Python cache
- `/site-packages/` - Installed packages
- `/.claude/hooks/` - Hook scripts themselves
- `/migrations/` - Database migrations
- `/test_*` - Test files

## Stop Hook: Automated Code Formatting

**Script**: `.claude/hooks/format-on-stop.py`
**Trigger**: After Claude finishes responding (all edits complete)
**Timeout**: 60 seconds

### Features

#### 1. Git-Based File Detection

The hook automatically detects modified files using Git:

```bash
git diff --name-only
```

Only processes files that:
- Have a `.py` extension
- Exist in the working directory
- Are not in excluded paths
- Have unstaged changes

#### 2. Batch Formatting Pipeline

Runs three tools in sequence:

**Black** - Code formatter
- Line length: 88 characters (default)
- String quotes: Double quotes
- Timeout: 30 seconds
- Prefers virtual environment installation at `venv/bin/black`

**isort** - Import sorter
- Organizing strategy: stdlib → third-party → local
- Alphabetical sorting within groups
- Timeout: 30 seconds
- Prefers virtual environment installation at `venv/bin/isort`

**Flake8** - Critical error checks
- Error codes: `E9,F63,F7,F82`
  - E9: Syntax errors
  - F63: Invalid comparison, invalid print syntax
  - F7: Syntax errors in type comments
  - F82: Undefined names
- Timeout: 30 seconds
- Prefers virtual environment installation at `venv/bin/flake8`

#### 3. Exclusion Patterns

The following file patterns are excluded from formatting:

- `venv/`, `.venv/`, `env/` - Virtual environments
- `__pycache__/` - Python cache
- `site-packages/` - Installed packages
- `.pytest_cache/` - Pytest cache
- `node_modules/` - Node.js dependencies
- `migrations/` - Database migrations (should not auto-format)
- `test_*` - Test files (optional exclusion)

#### 4. Detailed Reporting

Provides a concise summary of formatting results:

**Success Example**:
```
🎨 Formatted 3 file(s) | Black ✓ | isort ✓ | Flake8 ✓
```

**Error Example**:
```
🎨 Formatted 5 file(s) | Black ✓ | isort ✓ | Flake8 ✗

❌ Critical errors found:
  app/services/client/auth.py:42:5: F821 undefined name 'UserModel'
  app/api/client/v1/users.py:18:12: E999 SyntaxError: invalid syntax
  ... and 2 more
```

#### 5. Non-Blocking Execution

The hook is designed to never block Claude's workflow:

- Always exits with success code (0)
- Failures are reported but don't prevent continuation
- Tool not found warnings are informational only
- Silent exit when no files need formatting

### Output Format

The hook outputs JSON for proper display in Claude Code:

```json
{
  "systemMessage": "🎨 Formatted 3 file(s) | Black ✓ | isort ✓ | Flake8 ✓"
}
```

### Debugging

Debug logs are written to `/tmp/claude-stop-hook-debug.log`:

```
[2026-01-08 12:34:56] Stop hook invoked
```

## Tool Installation

Both hooks require formatting tools to be installed in the virtual environment:

```bash
# Activate virtual environment
source venv/bin/activate

# Install required tools
pip install black isort flake8
```

Verify installation:

```bash
which black   # Should show: /path/to/project/venv/bin/black
which isort   # Should show: /path/to/project/venv/bin/isort
which flake8  # Should show: /path/to/project/venv/bin/flake8
```

## Workflow Integration

### Developer Workflow

1. **Edit Code**: Claude writes or edits Python files
2. **Pre-Write Check**: Duplication detection runs before writing
3. **User Decision**: Review warnings/errors if any
4. **Write Complete**: Claude finishes all edits
5. **Auto-Format**: Stop hook formats all modified files
6. **Final Review**: Check formatting results

### Benefits

**Pre-Write Hook**:
- Prevents code duplication
- Enforces architectural patterns
- Catches design issues early
- Maintains code consistency

**Stop Hook**:
- Ensures consistent code style
- Catches syntax errors immediately
- Eliminates manual formatting
- Maintains import organization

### Performance Considerations

**Pre-Write Hook**:
- Analyzes only relevant files (same architecture layer)
- Limits candidate files to 30
- Uses AST instead of text comparison
- Timeout prevents hanging

**Stop Hook**:
- Only formats files with unstaged changes
- Batch processing is faster than per-file formatting
- Git detection is efficient
- No blocking on errors

## Troubleshooting

### Hook Not Running

**Check configuration**:
```bash
cat .claude/settings.json
```

**Verify script permissions**:
```bash
ls -l .claude/hooks/*.py
chmod +x .claude/hooks/*.py
```

**Check Python availability**:
```bash
python3 --version
```

### Tools Not Found

**Install missing tools**:
```bash
source venv/bin/activate
pip install black isort flake8
```

**Verify installation**:
```bash
venv/bin/black --version
venv/bin/isort --version
venv/bin/flake8 --version
```

### Timeout Issues

If hooks timeout frequently:

1. **Pre-Write Hook**: Reduce `MAX_CANDIDATE_FILES` in script
2. **Stop Hook**: Increase timeout in `.claude/settings.json`
3. **Both**: Optimize exclude patterns to skip more files

### False Positive Duplicates

If the pre-write hook flags legitimate similar code:

1. **Review the similarity details** to understand which dimensions match
2. **Consider refactoring** if the similarity is truly high
3. **Rename classes/methods** if functionality differs but structure is similar
4. **Adjust thresholds** in the script if needed (advanced)

## Customization

### Adjusting Similarity Thresholds

Edit `.claude/hooks/pre-write-intelligent.py`:

```python
SIMILARITY_THRESHOLDS = {
    "service": 60,   # Increase to be more lenient
    "model": 55,
    "api": 45,
    "util": 65,
    "schema": 45,
    "default": 60,
}
```

### Adjusting Similarity Weights

Edit `.claude/hooks/pre-write-intelligent.py`:

```python
KEYWORD_WEIGHTS = {
    "class_name": 0.20,      # Adjust importance
    "method_names": 0.25,
    "imports": 0.15,
    "decorators": 0.10,
    "base_classes": 0.15,
    "function_names": 0.15,
}
```

### Adding Exclusion Patterns

**Pre-Write Hook** - Edit `.claude/hooks/pre-write-intelligent.py`:
```python
exclude_patterns = [
    "/venv/",
    "/custom_exclude/",  # Add custom pattern
]
```

**Stop Hook** - Edit `.claude/hooks/format-on-stop.py`:
```python
EXCLUDE_PATTERNS = [
    "venv/",
    "custom_exclude/",  # Add custom pattern
]
```

### Adding Architecture Rules

Edit `.claude/hooks/pre-write-intelligent.py` in the `validate_architecture()` function:

```python
def validate_architecture(file_path: str, content: str) -> List[Dict]:
    violations = []

    # Add custom rule
    if "app/custom/" in file_path:
        if "forbidden_pattern" in content:
            violations.append({
                "rule": "Custom Rule",
                "severity": "error",
                "message": "Custom validation failed",
            })

    return violations
```

## Best Practices

### When Working with Hooks

1. **Read hook messages carefully** - They provide actionable insights
2. **Review similar files** before creating new ones
3. **Prefer extending existing code** over duplicating
4. **Let auto-formatting run** - Don't manually format before completion
5. **Check Flake8 errors** - Fix critical errors immediately

### When Disabling Hooks Temporarily

If you need to bypass hooks for a specific task:

1. **Move `.claude/settings.json`** to a backup location
2. **Complete your task**
3. **Restore `.claude/settings.json`**
4. **Run formatters manually**: `black . && isort . && flake8 --select=E9,F63,F7,F82 .`

**Not recommended for regular development**.

## References

- [Claude Code Hooks Documentation](https://github.com/anthropics/claude-code)
- [Black Documentation](https://black.readthedocs.io/)
- [isort Documentation](https://pycqa.github.io/isort/)
- [Flake8 Documentation](https://flake8.pycqa.org/)
- [Python AST Module](https://docs.python.org/3/library/ast.html)
