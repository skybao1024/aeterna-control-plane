# Claude Code Integration

This project includes comprehensive Claude Code integration with hooks, agents, and skills to enhance development workflow.

> **Note**: This documentation is for **developers**. Claude Code will automatically detect and use these features - no need to tell the AI how to use them through CLAUDE.md.

## Directory Structure

```
.claude/
├── hooks/                      # Pre/Stop tool execution hooks
│   ├── README.md              # Hook documentation
│   ├── pre-write-intelligent.py   # Smart code duplication detection
│   └── format-on-stop.py      # Auto-formatting on completion (Black, isort, Flake8)
├── agents/                     # Specialized AI agents
│   ├── architecture-advisor/  # Architecture guidance and design decisions
│   └── database-helper/       # Database, migrations, and query optimization
├── skills/                     # Project-specific skills
│   ├── sc-api-test/          # API endpoint testing with Docker
│   ├── sc-security/          # Security audit and OWASP compliance
│   └── sc-unit-test/         # Pytest unit testing with coverage
├── settings.json              # Team-shared settings (committed to git)
└── settings.local.json        # Personal settings (gitignored)
```

## Hooks

### Pre-Write Hook (Intelligent Code Analysis)
**File**: `hooks/pre-write-intelligent.py`

**Features**:
- AST-level code duplication detection (80% reduced false positives)
- Architecture rule validation (layer dependencies, singletons, configuration)
- Multi-dimensional similarity scoring
- Role-based thresholds (service/model/api/util/schema)
- Performance optimized with timeout protection

**Triggers**: Automatically runs before `Write` or `Edit` operations on Python files

**Configuration**: Edit thresholds and weights in `pre-write-intelligent.py`

### Stop Hook (Auto-Formatting on Completion)
**File**: `hooks/format-on-stop.py`

**Features**:
- Git-based detection of modified files
- Batch Black formatting (88 char lines, double quotes)
- Batch isort import sorting (stdlib → third-party → local)
- Flake8 critical error checking (E9, F63, F7, F82)
- Detailed reporting with status icons
- Non-blocking execution

**Triggers**: Automatically runs after Claude finishes responding (all edits complete)

**Dependencies**: `black`, `isort`, `flake8` (install via `pip install black isort flake8`)

## Agents

### @architecture-advisor
**Purpose**: Expert software architect for layered architecture and design patterns

**When to use**:
- File placement decisions ("Where should I put this feature?")
- Architecture pattern recommendations
- Dependency and circular import resolution
- Design pattern selection (Singleton, Factory, Strategy, etc.)
- Code organization and module structure

**Available Tools**: Sequential MCP, Context7 MCP, Grep, Read, Bash

**Example**: `@architecture-advisor How should I structure this email service?`

### @database-helper
**Purpose**: PostgreSQL, SQLAlchemy, and Alembic migration expert

**When to use**:
- Creating and reviewing migrations
- Query optimization and indexing
- Database schema design
- Transaction handling in async SQLAlchemy
- Migration troubleshooting

**Available Tools**: Sequential MCP, Context7 MCP, postgres_project MCP (if configured), Bash, Read

**Example**: `@database-helper How do I create a migration for adding phone_number field?`

## Skills

### /api-test (sc:api-test)
**Purpose**: Fast API endpoint testing with Docker and database validation

**Features**:
- Automatic Docker environment check
- API response testing (status codes, format validation)
- Database integrity validation using postgres MCP
- Quick feedback loop (60-90s total)

**When to use**:
- After implementing new API endpoint
- Debugging endpoint issues
- Quick validation during active conversation

**Auto-triggers**: Detects new API files and testing keywords in conversation

**Example**: `/api-test` or user asks "test this endpoint"

### /security (sc:security)
**Purpose**: Comprehensive security audit with OWASP Top 10 compliance

**Features**:
- Dependency vulnerability scanning (Safety, pip-audit)
- Code security pattern analysis (SQL injection, secrets, weak hashing)
- Authentication/authorization review
- API security validation
- Database security audit
- OWASP Top 10 compliance checking

**When to use**:
- Pre-deployment security check
- After implementing authentication
- Regular security audits
- Dependency updates

**Auto-triggers**: Detects security-related file changes or keywords

**Example**: `/security` or user asks "run security audit"

**Dependencies**: `safety`, `pip-audit`, `bandit` (install via `pip install safety pip-audit bandit`)

### /unit-test (sc:unit-test)
**Purpose**: Pytest unit testing with coverage analysis and test generation

**Features**:
- Automatic test generation for untested functions
- Code coverage analysis (≥80% target)
- AAA pattern (Arrange-Act-Assert) test structure
- Async test support with pytest-asyncio
- Mock strategy for external dependencies

**When to use**:
- After implementing service layer methods
- TDD workflow (write tests first)
- Coverage improvement
- Regression testing

**Auto-triggers**: Detects service layer changes or testing keywords

**Example**: `/unit-test` or user asks "write tests"

**Dependencies**: `pytest`, `pytest-cov`, `pytest-asyncio` (install via `pip install pytest pytest-cov pytest-asyncio`)

## Configuration Files

### settings.json (Team Shared)
**Committed to git** - Contains hooks configuration shared across team

```json
{
  "hooks": {
    "PreToolUse": [{
      "matcher": "Edit|Write",
      "hooks": [{
        "type": "command",
        "command": "python3 \"$CLAUDE_PROJECT_DIR\"/.claude/hooks/pre-write-intelligent.py",
        "timeout": 10
      }]
    }],
    "Stop": [{
      "hooks": [{
        "type": "command",
        "command": "python3 \"$CLAUDE_PROJECT_DIR\"/.claude/hooks/format-on-stop.py",
        "timeout": 60
      }]
    }]
  }
}
```

### settings.local.json (Personal)
**Gitignored** - Contains personal permission preferences

**Setup**:
```bash
# Copy example file and customize
cp .claude/settings.local.json.example .claude/settings.local.json
```

**Example configuration**:
```json
{
  "permissions": {
    "defaultMode": "default",
    "allow": [
      "Bash(python:*)",
      "Bash(docker-compose:*)",
      "Read",
      "Edit",
      "Write"
    ]
  },
  "enableAllProjectMcpServers": true
}
```

## Best Practices

### For Development
1. Install hook dependencies: `pip install black isort flake8`
2. Configure personal permissions in `settings.local.json`
3. Use agents for architecture and database decisions
4. Run `/api-test` after implementing endpoints
5. Run `/unit-test` for service layer changes
6. Run `/security` before deployment

### For Team Collaboration
1. Commit `.claude/hooks/`, `.claude/agents/`, `.claude/skills/` to git
2. Commit `.claude/settings.json` for shared hooks
3. Don't commit `.claude/settings.local.json` (personal settings)
4. Document custom skills in project README
5. Share agent usage patterns in team documentation

### Performance Tips
1. Hooks run automatically - keep them fast (<10s for pre-write, <60s for stop)
2. Skills are manual - can take longer (60-240s depending on scope)
3. Agents provide consultation - use for planning, not execution
4. Use `--help` flag with skills for detailed usage information

## Troubleshooting

### Hook not running
- Check Python 3 is available: `python3 --version`
- Verify hook file permissions: `chmod +x .claude/hooks/*.py`
- Check hook timeout settings in `settings.json`

### Skill not found
- Verify skill directory exists: `ls -la .claude/skills/`
- Check SKILL.md file format (YAML frontmatter required)
- Restart Claude Code to refresh skill detection

### Agent not responding
- Verify agent instructions.md exists
- Check agent name in frontmatter matches usage
- Use exact agent name: `@architecture-advisor` (not `@architect`)

### Dependencies missing
- Install hook dependencies: `pip install black isort flake8`
- Install skill dependencies: `pip install safety pip-audit bandit pytest pytest-cov`
- Activate virtual environment before installing: `source venv/bin/activate`
