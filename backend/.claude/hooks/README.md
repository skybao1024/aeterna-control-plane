# Claude Code Hooks - Quick Reference Guide

## Overview

This project uses two Claude Code hooks to maintain code quality:

1. **PreToolUse Hook** - Intelligent code duplication detection and architecture validation
2. **Stop Hook** - Automated code formatting after Claude completes editing

Benefits:
- ✅ 80% reduction in false positives (from 50%+ down to <10%)
- ✅ Understands code structure and responsibilities
- ✅ Architecture-aware (different thresholds for different layers)
- ✅ Automatic code formatting (Black + isort + Flake8)
- ✅ Performance optimization and resource protection

## Quick Start

The hooks are automatically enabled with no additional configuration required. Ready to use after cloning the project.

## Hook 1: PreToolUse - Code Duplication Detection

**Script**: `pre-write-intelligent.py`
**Trigger**: Before `Edit` or `Write` tool execution
**Timeout**: 10 seconds

### Core Features

- **AST Structure Analysis**: Deep understanding of code structure (classes, methods, inheritance)
- **Multi-dimensional Similarity Scoring**: Comprehensive evaluation across 6 dimensions
  - Class names (20% weight)
  - Method names (25% weight)
  - Imports (15% weight)
  - Decorators (10% weight)
  - Base classes (15% weight)
  - Function names (15% weight)
- **Architecture Rule Validation**: Automatic detection of violations
  - Layer dependency violations
  - Singleton pattern violations
  - Configuration access violations
- **Intelligent Search**: Smart search for similar code based on file roles
- **Performance Protection**: File size limits, timeout protection, resource constraints

### Architecture-Aware Thresholds

Different code layers have different similarity thresholds:

| File Role | Threshold | Rationale |
|-----------|-----------|-----------|
| Service layer | 60% | Lower threshold to catch exact copies |
| Model layer | 55% | Catch duplicate data models |
| API layer | 45% | Loose check (endpoints may be similar) |
| Schema layer | 45% | Loose check (DTOs may be similar) |
| Utility layer | 65% | Stricter check for shared utilities |
| Default | 60% | General purpose threshold |

### Detection Behavior

**Critical Issues (Blocks Write)**:
- Architecture rule error-level violations
- High similarity ≥80% indicating severe duplication
- **Action**: Requests user confirmation

**Warnings (Allow Write but Notify)**:
- Architecture rule warning-level violations
- Similarity exceeds threshold but <80%
- **Action**: Displays warning but allows write

**Silent Pass**:
- Similarity <60%
- No rule violations
- **Action**: Allows write without notification

### Custom Configuration

Edit `pre-write-intelligent.py` to adjust:

**Similarity Thresholds**:
```python
SIMILARITY_THRESHOLDS = {
    "service": 60,   # Service layer
    "model": 55,     # Model layer
    "api": 45,       # API layer
    "util": 65,      # Utility classes
    "schema": 45,    # Schema
    "default": 60,   # Default
}
```

**Weight Adjustments**:
```python
KEYWORD_WEIGHTS = {
    "class_name": 0.20,      # Class name similarity
    "method_names": 0.25,    # Method name similarity
    "imports": 0.15,         # Import dependency similarity
    "decorators": 0.10,      # Decorator similarity
    "base_classes": 0.15,    # Inheritance relationship similarity
    "function_names": 0.15,  # Function name similarity
}
```

**Performance Configuration**:
```python
MAX_FILE_SIZE_MB = 5          # Maximum file size (avoid memory issues)
FIND_TIMEOUT = 5              # find command timeout (seconds)
MAX_CANDIDATE_FILES = 30      # Maximum number of candidate files to analyze
```

## Hook 2: Stop - Automated Code Formatting

**Script**: `format-on-stop.py`
**Trigger**: After Claude finishes responding (all edits complete)
**Timeout**: 60 seconds

### Core Features

- **Git-Based File Detection**: Automatically detects modified files using `git diff`
- **Batch Formatting Pipeline**: Runs three tools in sequence
  - **Black**: Code formatter (88 char line length, double quotes)
  - **isort**: Import sorter (stdlib → third-party → local)
  - **Flake8**: Critical error checks (E9, F63, F7, F82)
- **Smart Exclusion**: Skips virtual environments, migrations, test files, cache
- **Detailed Reporting**: Provides concise summary with status icons
- **Non-Blocking**: Never blocks Claude's workflow

### Formatting Tools

| Tool | Purpose | Timeout | Configuration |
|------|---------|---------|---------------|
| Black | Code formatting | 30s | 88 char lines, double quotes |
| isort | Import sorting | 30s | stdlib → third-party → local |
| Flake8 | Critical errors | 30s | E9, F63, F7, F82 only |

### Exclusion Patterns

The following patterns are automatically excluded:

- `venv/`, `.venv/`, `env/` - Virtual environments
- `__pycache__/` - Python cache
- `site-packages/` - Installed packages
- `.pytest_cache/` - Pytest cache
- `node_modules/` - Node.js dependencies
- `migrations/` - Database migrations
- `test_*` - Test files (optional)

### Output Examples

**Success**:
```
🎨 Formatted 3 file(s) | Black ✓ | isort ✓ | Flake8 ✓
```

**With Errors**:
```
🎨 Formatted 5 file(s) | Black ✓ | isort ✓ | Flake8 ✗

❌ Critical errors found:
  app/services/client/auth.py:42:5: F821 undefined name 'UserModel'
  app/api/client/v1/users.py:18:12: E999 SyntaxError: invalid syntax
  ... and 2 more
```

### Custom Configuration

Edit `format-on-stop.py` to adjust:

**Timeouts**:
```python
GIT_TIMEOUT = 10        # seconds
FORMAT_TIMEOUT = 30     # seconds
FLAKE8_TIMEOUT = 30     # seconds
```

**Exclusion Patterns**:
```python
EXCLUDE_PATTERNS = [
    "venv/",
    ".venv/",
    "env/",
    "__pycache__/",
    "site-packages/",
    ".pytest_cache/",
    "node_modules/",
    "migrations/",
    "test_",
    # Add custom patterns here
]
```

**Flake8 Error Codes**:
```python
FLAKE8_CRITICAL_ERRORS = "E9,F63,F7,F82"  # Only critical errors
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
which black   # Should show: venv/bin/black
which isort   # Should show: venv/bin/isort
which flake8  # Should show: venv/bin/flake8
```

## Hook Configuration

**Configuration File**: `.claude/settings.json`

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

## Workflow Integration

### Developer Workflow

1. **Edit Code**: Claude writes or edits Python files
2. **Pre-Write Check**: Duplication detection runs before writing
3. **User Decision**: Review warnings/errors if any
4. **Write Complete**: Claude finishes all edits
5. **Auto-Format**: Stop hook formats all modified files
6. **Final Review**: Check formatting results

### Benefits

**PreToolUse Hook**:
- Prevents code duplication
- Enforces architectural patterns
- Catches design issues early
- Maintains code consistency

**Stop Hook**:
- Ensures consistent code style
- Catches syntax errors immediately
- Eliminates manual formatting
- Maintains import organization

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

1. **PreToolUse Hook**: Reduce `MAX_CANDIDATE_FILES` in script (30 → 20)
2. **Stop Hook**: Increase timeout in `.claude/settings.json` (60 → 90)
3. **Both**: Optimize exclude patterns to skip more files

### False Positive Duplicates

If the pre-write hook flags legitimate similar code:

1. **Review the similarity details** to understand which dimensions match
2. **Consider refactoring** if the similarity is truly high
3. **Rename classes/methods** if functionality differs but structure is similar
4. **Adjust thresholds** in the script if needed

### Temporarily Disable Hooks

If you need to bypass hooks for a specific task:

**Option 1: Comment out in settings.json**:
```json
{
  "hooks": {
    // "PreToolUse": [...],
    // "Stop": [...]
  }
}
```

**Option 2: Move settings.json temporarily**:
```bash
mv .claude/settings.json .claude/settings.json.bak
# Complete your task
mv .claude/settings.json.bak .claude/settings.json
```

**Run formatters manually after**:
```bash
source venv/bin/activate
black .
isort .
flake8 --select=E9,F63,F7,F82 .
```

## Performance Optimization

### Large Projects

- Reduce `MAX_CANDIDATE_FILES` (30 → 20)
- Reduce `FIND_TIMEOUT` (5 → 3)
- Add more exclusion patterns

### Small Projects

- Increase `MAX_CANDIDATE_FILES` (30 → 50)
- Increase `FIND_TIMEOUT` (5 → 10)
- More comprehensive detection

### Specific Directories

Edit the `find_similar_files` function in `pre-write-intelligent.py` to add custom exclusion patterns.

## Multi-Developer Collaboration

### Team Collaboration

- All developers use the same hook configuration
- Unified code quality standards
- Shared architecture rule validation

### CI/CD Environment

- Hook validation can be executed in CI
- Fast detection to ensure code quality
- Optional selective enabling/disabling of specific rules

### Onboarding New Members

1. Hooks automatically enabled after cloning the project
2. Refer to this documentation to understand features
3. Adjust configuration as needed
4. Install required tools (`black`, `isort`, `flake8`)

## Best Practices

### When Working with Hooks

1. **Read hook messages carefully** - They provide actionable insights
2. **Review similar files** before creating new ones
3. **Prefer extending existing code** over duplicating
4. **Let auto-formatting run** - Don't manually format before completion
5. **Check Flake8 errors** - Fix critical errors immediately

### Code Quality Standards

- Follow PEP 8 standards (enforced by Black)
- Maintain consistent import order (enforced by isort)
- Fix critical syntax errors (detected by Flake8)
- Avoid code duplication (detected by PreToolUse hook)
- Respect architecture patterns (validated by PreToolUse hook)

## Frequently Asked Questions

### Q: What to do about high false positive rates?

**A**: Increase the threshold for the corresponding file role (e.g., `service: 60 → 70`)

### Q: What to do if detection is slow?

**A**:
- Reduce `MAX_CANDIDATE_FILES` (30 → 20)
- Reduce `FIND_TIMEOUT` (5 → 3)
- Exclude more directories that don't need detection

### Q: How to temporarily disable hooks?

**A**: Comment out the hook configuration in `.claude/settings.json`

### Q: Hook errors preventing file writes?

**A**:
1. Check if Python environment is working properly
2. Review detailed error messages in stderr output
3. Temporarily disable hook to complete urgent changes
4. Re-enable after resolving the error

### Q: Can I customize the formatting rules?

**A**: Yes, you can configure Black and isort in `pyproject.toml` or their respective config files:

```toml
# pyproject.toml
[tool.black]
line-length = 88
target-version = ['py312']

[tool.isort]
profile = "black"
```

### Q: Why does the Stop hook not format my files?

**A**: Check these common issues:
1. Tools not installed in virtual environment
2. Files not detected by git (not in git repository or already committed)
3. Files excluded by exclusion patterns
4. Files have syntax errors preventing parsing

## Documentation

**Detailed Documentation**: See `docs/development/claude-hooks.md` for comprehensive information including:
- AST analysis principles
- Similarity calculation algorithms
- Complete configuration reference
- Advanced customization examples

**Project Guidelines**: See `CLAUDE.md` for:
- Code style requirements
- Dependency injection patterns
- Database field type requirements
- Development commands

## Support

- 📖 **Detailed Documentation**: `docs/development/claude-hooks.md`
- 📖 **Project Guidelines**: `CLAUDE.md`
- 🤖 **Architecture Consultation**: `@architecture-advisor`
- 💬 **Issue Feedback**: Project Issues

---

**Version**: v4.0 - Dual Hook System
**Last Updated**: 2026-01-08
**Hooks**: `pre-write-intelligent.py` + `format-on-stop.py`
