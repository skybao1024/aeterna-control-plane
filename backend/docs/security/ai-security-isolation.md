# AI Security Isolation Guide for Claude Code

## Overview

When using AI assistants through third-party proxy services, all conversation data passes through the proxy provider. This creates a security risk where sensitive credentials (API keys, database passwords, AWS secrets) could be exposed in conversation logs.

This guide provides a comprehensive security isolation strategy at the Claude Code level to protect sensitive configuration files from AI access while maintaining full development capabilities.

## The Problem

**Risk Scenario:**
1. You use Claude Code through a third-party proxy/relay service
2. AI needs to help debug external services (AWS, databases, payment APIs)
3. AI reads `.env` or configuration files to understand setup
4. **Sensitive credentials are now in conversation logs accessible to proxy provider**

**Impact:**
- Database passwords exposed
- API keys compromised
- Cloud service credentials leaked
- Production systems at risk

## The Solution: Three-Layer Defense

### Layer 1: Technical Protection (Claude Code Permissions)

Configure Claude Code's permission system to physically block access to sensitive files.

#### Configuration Location

Edit `~/.claude/settings.json` (global settings for all projects):

```json
{
  "permissions": {
    "allow": [
      "Read",
      "Bash(cat:*)",
      "Bash(grep:*)"
    ],
    "deny": [
      "Read(*.env)",
      "Read(*.env.local)",
      "Read(*.env.production)",
      "Read(*/.env)",
      "Read(*/.env.local)",
      "Read(*/.env.production)",
      "Bash(cat *.env*)",
      "Bash(cat .env*)",
      "Bash(grep * *.env*)"
    ],
    "ask": []
  }
}
```

**What this does:**
- Blocks `Read` tool from accessing any `.env*` files
- Blocks `cat` and `grep` commands on `.env*` files
- Works across all file paths and patterns
- AI physically cannot access these files

**Verification:**

Test the configuration by asking AI to read your `.env` file:

```
You: "Read the .env file"
AI: [Attempts to read]
Result: "File is in a directory that is denied by your permission settings."
```

✅ If you see this error, protection is working correctly.

### Layer 2: Instruction Protection (Project Documentation)

Add explicit security rules to your project's `CLAUDE.md` file.

#### Add to CLAUDE.md

Place this at the **very top** of your `CLAUDE.md` file (highest priority):

```markdown
## CRITICAL SECURITY RULES (HIGHEST PRIORITY)

### Environment File Protection (MANDATORY)

**⚠️ ABSOLUTE PROHIBITION: NEVER read, display, or reference actual values from `.env` files**

**Why this matters:**
- All AI conversations pass through third-party proxy services
- Proxy providers can log and access complete conversation history
- `.env` files contain production credentials (database passwords, API keys, secrets)
- One accidental read can expose all production systems

**FORBIDDEN Actions:**
- ❌ NEVER use `Read` tool on `.env`, `.env.local`, `.env.production`
- ❌ NEVER use `cat`, `grep`, or any command to display `.env` contents
- ❌ NEVER ask user to paste `.env` contents
- ❌ NEVER display actual credential values in responses
- ❌ NEVER use real credentials in example code

**REQUIRED Actions:**
- ✅ ALWAYS use `os.getenv('VARIABLE_NAME')` in code (reference only)
- ✅ ALWAYS use placeholders in examples: `***REDACTED***`, `<SECRET>`, `[MASKED]`
- ✅ ALWAYS read `.env.example` or `.env.template` for structure (never `.env`)
- ✅ ALWAYS generate test scripts that user executes locally
- ✅ ALWAYS remind user to run scripts locally with real credentials

**When Debugging External Services (AWS, databases, APIs, payment gateways):**

Generate test scripts with environment variable references:

```python
# ✅ CORRECT: AI generates code with environment variable references
import os
from dotenv import load_dotenv

# User runs locally - real credentials loaded at runtime
load_dotenv('.env')

def test_service():
    """Test external service - user runs locally with real credentials"""
    api_key = os.getenv('SERVICE_API_KEY')  # Reference only - AI never sees value

    # Test logic here
    pass

if __name__ == "__main__":
    test_service()
```

**Workflow:**
1. AI generates test script with `os.getenv()` references
2. User saves script to file (e.g., `test_service.py`)
3. User runs locally: `python test_service.py`
4. Real credentials loaded from `.env` at runtime (AI never sees them)
5. User shares error messages (without credentials) back to AI if needed

**If User Asks to Debug Configuration Issues:**
- Ask for error messages, stack traces, or symptoms
- Ask which environment variables are involved (names only, not values)
- Read `.env.example` or `.env.template` to understand structure
- Generate diagnostic code that user runs locally
- NEVER ask for actual credential values

**Emergency Override:**
If user explicitly pastes credentials in chat:
1. Immediately warn: "⚠️ SECURITY WARNING: You've shared sensitive credentials in this conversation"
2. Recommend: "Please rotate these credentials immediately after this session"
3. Suggest: "Use test/sandbox credentials for AI debugging in the future"
```

### Layer 3: Safe Configuration Files

Maintain template files that are safe to share with AI.

#### File Structure

```
project/
├── .env                    # Real credentials - PROTECTED
├── .env.local             # Local overrides - PROTECTED
├── .env.production        # Production secrets - PROTECTED
├── .env.example           # Safe template - AI can read
└── .env.template          # Safe template - AI can read
```

#### Example .env.example

```bash
# Environment Configuration Template
# Safe to share with AI assistants
# Copy to .env and fill in real values

# Environment
ENV=development

# Database Configuration
DATABASE_URL=postgresql://user:password@localhost:5432/dbname
DB_HOST=localhost
DB_PORT=5432
DB_USER=your_db_user
DB_PASSWORD=***REDACTED***
DB_NAME=your_db_name

# Redis Configuration
REDIS_URL=redis://localhost:6379
REDIS_PASSWORD=***REDACTED***

# API Keys
API_KEY=***REDACTED***
SECRET_KEY=***REDACTED***

# AWS Configuration
AWS_ACCESS_KEY_ID=***REDACTED***
AWS_SECRET_ACCESS_KEY=***REDACTED***
AWS_REGION=us-east-1
AWS_BUCKET_NAME=your-bucket-name

# Third-Party Services
STRIPE_SECRET_KEY=***REDACTED***
OPENAI_API_KEY=***REDACTED***
SENDGRID_API_KEY=***REDACTED***
```

## Language-Specific Examples

### Python (Django/Flask/FastAPI)

```python
# config.py - AI can see this
import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # AI sees references, not values
    DATABASE_URL = os.getenv('DATABASE_URL')
    SECRET_KEY = os.getenv('SECRET_KEY')
    AWS_ACCESS_KEY = os.getenv('AWS_ACCESS_KEY_ID')
```

### Node.js (Express/NestJS)

```javascript
// config.js - AI can see this
require('dotenv').config();

module.exports = {
  // AI sees references, not values
  databaseUrl: process.env.DATABASE_URL,
  secretKey: process.env.SECRET_KEY,
  awsAccessKey: process.env.AWS_ACCESS_KEY_ID
};
```

### Go

```go
// config.go - AI can see this
package config

import (
    "os"
    "github.com/joho/godotenv"
)

type Config struct {
    DatabaseURL string
    SecretKey   string
    AWSAccessKey string
}

func Load() *Config {
    godotenv.Load()

    return &Config{
        // AI sees references, not values
        DatabaseURL:  os.Getenv("DATABASE_URL"),
        SecretKey:    os.Getenv("SECRET_KEY"),
        AWSAccessKey: os.Getenv("AWS_ACCESS_KEY_ID"),
    }
}
```

### Ruby (Rails)

```ruby
# config/application.rb - AI can see this
module YourApp
  class Application < Rails::Application
    # AI sees references, not values
    config.database_url = ENV['DATABASE_URL']
    config.secret_key_base = ENV['SECRET_KEY_BASE']
    config.aws_access_key = ENV['AWS_ACCESS_KEY_ID']
  end
end
```

### Java (Spring Boot)

```java
// application.properties - AI can see this
# AI sees references, not values
spring.datasource.url=${DATABASE_URL}
spring.datasource.username=${DB_USER}
spring.datasource.password=${DB_PASSWORD}

# application.yml alternative
spring:
  datasource:
    url: ${DATABASE_URL}
    username: ${DB_USER}
    password: ${DB_PASSWORD}
```

### .NET (C#)

```csharp
// appsettings.json - AI can see this
{
  "ConnectionStrings": {
    "DefaultConnection": "Server=${DB_HOST};Database=${DB_NAME};User=${DB_USER};Password=${DB_PASSWORD};"
  },
  "AWS": {
    "AccessKey": "${AWS_ACCESS_KEY_ID}",
    "SecretKey": "${AWS_SECRET_ACCESS_KEY}"
  }
}
```

## Testing External Services Safely

### Example: Testing AWS S3 Connection

**AI generates this code:**

```python
# test_aws_s3.py
import os
import boto3
from dotenv import load_dotenv

# Load real credentials locally (AI never sees them)
load_dotenv('.env')

def test_s3_connection():
    """Test AWS S3 connection"""
    # AI only sees os.getenv() references
    s3 = boto3.client(
        's3',
        aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
        aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
        region_name=os.getenv('AWS_REGION')
    )

    try:
        response = s3.list_buckets()
        print(f"✓ Success! Found {len(response['Buckets'])} buckets")
        for bucket in response['Buckets']:
            print(f"  - {bucket['Name']}")
    except Exception as e:
        print(f"✗ Error: {e}")

if __name__ == "__main__":
    test_s3_connection()
```

**You run locally:**

```bash
python test_aws_s3.py
```

**If there's an error, share only the error message (no credentials):**

```
✗ Error: An error occurred (InvalidAccessKeyId) when calling the ListBuckets operation: The AWS Access Key Id you provided does not exist in our records.
```

AI can help debug based on the error message without ever seeing your actual credentials.

### Example: Testing Database Connection

**AI generates this code:**

```python
# test_database.py
import os
from sqlalchemy import create_engine
from dotenv import load_dotenv

load_dotenv('.env')

def test_database_connection():
    """Test database connection"""
    # AI only sees os.getenv() reference
    database_url = os.getenv('DATABASE_URL')

    try:
        engine = create_engine(database_url)
        with engine.connect() as conn:
            result = conn.execute("SELECT version();")
            version = result.fetchone()[0]
            print(f"✓ Connected! PostgreSQL version: {version}")
    except Exception as e:
        print(f"✗ Error: {e}")

if __name__ == "__main__":
    test_database_connection()
```

## Git Protection

### Update .gitignore

Ensure sensitive files are never committed:

```gitignore
# Environment files
.env
.env.local
.env.production
.env.*.local

# Keep only templates
!.env.example
!.env.template
```

### Pre-commit Hook (Optional)

Prevent accidental commits of sensitive files:

```bash
#!/bin/bash
# .git/hooks/pre-commit

# Check for sensitive files
if git diff --cached --name-only | grep -E "^\.env$|\.env\.local$|\.env\.production$"; then
    echo "❌ ERROR: Attempting to commit sensitive .env file!"
    echo "Please use .env.example instead"
    exit 1
fi

# Check for sensitive content
if git diff --cached | grep -iE "password|secret_key|api_key" | grep -v "REDACTED\|MASKED\|example"; then
    echo "⚠️  WARNING: Potential sensitive data in commit"
    echo "Please review your changes"
    exit 1
fi
```

## Verification Checklist

Use this checklist to verify your security setup:

### ✅ Technical Protection
- [ ] Updated `~/.claude/settings.json` with deny rules
- [ ] Tested by asking AI to read `.env` (should be blocked)
- [ ] Verified error message: "File is in a directory that is denied by your permission settings"

### ✅ Instruction Protection
- [ ] Added CRITICAL SECURITY RULES to `CLAUDE.md`
- [ ] Placed security rules at the top (highest priority)
- [ ] Included workflow examples for debugging

### ✅ Safe Configuration Files
- [ ] Created `.env.example` or `.env.template` with placeholders
- [ ] Updated `.gitignore` to exclude real `.env` files
- [ ] Verified templates contain no real credentials

### ✅ Team Awareness
- [ ] Shared this guide with team members
- [ ] Conducted security training session
- [ ] Established credential rotation policy

## Best Practices

### DO ✅

1. **Always use environment variable references in code**
   ```python
   api_key = os.getenv('API_KEY')  # Good
   ```

2. **Use placeholders in documentation**
   ```
   API_KEY=***REDACTED***  # Good
   ```

3. **Generate test scripts for local execution**
   ```python
   # AI generates, you run locally
   load_dotenv('.env')
   ```

4. **Share error messages without credentials**
   ```
   Error: Invalid API key format  # Good - no actual key
   ```

5. **Use test/sandbox credentials when possible**
   ```
   STRIPE_SECRET_KEY=sk_test_...  # Test mode key
   ```

### DON'T ❌

1. **Never paste credentials in chat**
   ```
   API_KEY=sk_live_abc123xyz  # BAD - exposed to proxy
   ```

2. **Never ask AI to read `.env` directly**
   ```
   "Read my .env file"  # BAD - will expose credentials
   ```

3. **Never hardcode credentials in code**
   ```python
   api_key = "sk_live_abc123"  # BAD - visible in conversation
   ```

4. **Never share connection strings with credentials**
   ```
   postgresql://user:password@host/db  # BAD - password exposed
   ```

5. **Never use production credentials for testing**
   ```
   AWS_ACCESS_KEY_ID=AKIA...  # BAD if production key
   ```

## Incident Response

### If Credentials Are Accidentally Exposed

1. **Immediate Actions:**
   - Stop the conversation immediately
   - Rotate all exposed credentials
   - Review conversation history for other exposures

2. **Credential Rotation:**
   - Database passwords: Change immediately
   - API keys: Regenerate new keys
   - AWS credentials: Deactivate and create new
   - JWT secrets: Generate new secret, invalidate old tokens

3. **Audit:**
   - Check access logs for unauthorized usage
   - Review recent API calls for suspicious activity
   - Monitor for unusual database queries

4. **Prevention:**
   - Review and strengthen permission rules
   - Update team training
   - Consider using separate test credentials

## Additional Security Measures

### 1. Use Separate Test Credentials

Create limited-permission credentials for AI-assisted debugging:

```bash
# .env.test (safe to expose if needed)
AWS_ACCESS_KEY_ID=AKIA...test_account
AWS_SECRET_ACCESS_KEY=...test_account
STRIPE_SECRET_KEY=sk_test_...
DATABASE_URL=postgresql://test_user:test_pass@localhost/test_db
```

### 2. Implement Credential Rotation

Regularly rotate credentials even without exposure:

- Database passwords: Every 90 days
- API keys: Every 180 days
- AWS credentials: Every 90 days
- JWT secrets: Every 365 days

### 3. Use Secret Management Services

For production environments, consider:

- **AWS Secrets Manager**: Centralized secret storage
- **HashiCorp Vault**: Enterprise secret management
- **Azure Key Vault**: Microsoft cloud secrets
- **Google Secret Manager**: GCP secret storage

### 4. Monitor Access Logs

Set up alerts for:

- Failed authentication attempts
- Unusual API usage patterns
- Access from unexpected IP addresses
- High-volume data exports

## Conclusion

By implementing this three-layer security isolation strategy, you can safely use AI assistants for development while protecting sensitive credentials from exposure through proxy services.

**Key Takeaways:**

1. **Technical Protection**: Claude Code permissions physically block access
2. **Instruction Protection**: Clear rules in CLAUDE.md guide AI behavior
3. **Safe Workflow**: AI generates code with references, you execute locally
4. **Zero Trust**: AI never sees actual credential values

This approach allows you to leverage AI assistance for debugging external services, database connections, and API integrations without compromising security.

---

**Questions or Issues?**

If you encounter any problems with this security setup or have questions about specific use cases, please contact your security team or refer to the Claude Code documentation.

**Last Updated:** 2026-03-11
