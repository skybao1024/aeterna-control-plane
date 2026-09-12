# FastAPI Template

> Modern enterprise-grade Web API template project based on FastAPI

[![FastAPI](https://img.shields.io/badge/FastAPI-0.136.1-009688.svg)](https://fastapi.tiangolo.com)
[![Python](https://img.shields.io/badge/Python-3.14+-3776ab.svg)](https://www.python.org)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15+-336791.svg)](https://www.postgresql.org)
[![Redis](https://img.shields.io/badge/Redis-7+-dc382d.svg)](https://redis.io)
[![Docker](https://img.shields.io/badge/Docker-Supported-2496ed.svg)](https://www.docker.com)

## 🚀 Key Features

### Core Architecture
- **Dual-Client Architecture**: Separated client API and backoffice management API
- **Separated Documentation**: Independent Swagger documentation system with environment-controlled access
- **Async-First**: Full async architecture for high concurrency
- **Enterprise Design**: Complete authentication, authorization, and monitoring system

### Technology Stack
- 🏗️ **Web Framework**: FastAPI 0.136.1 (high-performance async framework)
- 🗄️ **Database**: PostgreSQL + SQLAlchemy 2.0 (async ORM)
- 🔄 **Cache**: Redis 7+ (cache + message queue)
- ⚡ **Background Tasks**: Celery 5.6.3 (distributed task queue)
- 🔐 **Authentication**: JWT authentication + permission management
- ☁️ **Cloud Storage**: AWS S3 integration
- 📧 **Email Service**: SMTP / Brevo API support
- 🐳 **Containerization**: Docker + Docker Compose

### Development Features
- 📊 **Smart Monitoring**: Health checks + structured logging
- 🧪 **Complete Testing**: Unit test + integration test framework
- 📝 **API Export**: OpenAPI 3.0 JSON export functionality
- 🔧 **Development Tools**: Hot reload + debugging support
- 📚 **Complete Documentation**: Architecture docs + development guides

## 📋 Quick Start

### Requirements

- Python 3.14+
- Docker & Docker Compose
- PostgreSQL 15+ (optional, can use Docker)
- Redis 7+ (optional, can use Docker)

### 1. Clone Project

```bash
git clone <repository-url>
cd fastapi-template
```

### 2. Environment Configuration

```bash
# Copy environment configuration file
cp .env.example .env

# Edit configuration file
vim .env
```

**Required Environment Variables**:
```env
# Environment setting
ENV=development

# Database configuration
POSTGRES_USER=demo
POSTGRES_PASSWORD=demo123
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=demo

# Redis configuration
REDIS_HOST=redis
REDIS_PORT=6379
REDIS_PASSWORD=

# JWT secret
SECRET_KEY=your-secret-key-here

# AWS configuration (optional)
AWS_ACCESS_KEY_ID=your-access-key
AWS_SECRET_ACCESS_KEY=your-secret-key
AWS_REGION=us-east-1
AWS_BUCKET_NAME=your-bucket

# Email configuration (optional)
ADMIN_EMAIL=admin@example.com
```

### 3. Docker Startup (Recommended)

```bash
# Start all services
docker-compose up -d

# Check service status
docker-compose ps

# View logs
docker-compose logs -f fastapi-app
```

### 4. Local Development Startup

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt

# Run database migrations
alembic upgrade head

# Start development server
python main.py
```

### 5. Verify Installation

Visit the following addresses to verify successful installation:

- **Health Check**: http://localhost:8001/api/v1/config/health
- **Documentation Navigation**: http://localhost:8001/ (development environment only)

## 📖 API Documentation

### Documentation Access URLs

| Documentation Type | URL | Description |
|---------|------|------|
| 🏠 **Root Navigation** | http://localhost:8001/ | Development environment documentation navigation |
| 📱 **Client Swagger** | http://localhost:8001/client/docs | Client API interactive documentation |
| 📱 **Client ReDoc** | http://localhost:8001/client/redoc | Client API reading documentation |
| 🔧 **Backoffice Swagger** | http://localhost:8001/backoffice/docs | Backoffice management API documentation |
| 🔧 **Backoffice ReDoc** | http://localhost:8001/backoffice/redoc | Backoffice management API reading documentation |
| 💾 **API Export** | http://localhost:8001/api-docs/ | OpenAPI JSON export |

### Environment Control

- **Development Environment** (`ENV=development`): Shows complete documentation navigation
- **Production Environment** (`ENV=production`): Hides documentation navigation for enhanced security
- **Preview Environment** (`ENV=preview`): Same as development environment

### Authentication Usage

**Client API**: No authentication required, test directly

**Backoffice Management API**: Requires JWT authentication
1. Access `/api/v1/backoffice/auth/login` to get token
2. Click 🔒 **Authorize** in the top right corner of Swagger UI
3. Enter: `Bearer <your-token>`
4. After completing authentication, you can test all backoffice endpoints

## 🏗️ Project Architecture

### Directory Structure

```
fastapi-template/
├── app/                          # Main application directory
│   ├── api/                      # API routing layer
│   │   ├── client/v1/            # Client API v1
│   │   ├── backoffice/v1/        # Backoffice management API v1
│   │   └── docs_export.py        # API documentation export
│   ├── core/                     # Core system configuration
│   │   ├── config.py             # Environment configuration
│   │   ├── security.py           # Security configuration
│   │   └── log_config.py         # Logging configuration
│   ├── configs/                  # Application configuration
│   │   ├── client_swagger_config.py      # Client Swagger configuration
│   │   ├── backoffice_swagger_config.py  # Backoffice Swagger configuration
│   │   └── docs_apps.py          # Documentation application configuration
│   ├── route/                    # Route management
│   │   ├── route.py              # Main route configuration
│   │   └── router_registry.py    # Route registration center
│   ├── models/                   # Data models
│   ├── schemas/                  # Pydantic schemas
│   ├── services/                 # Business logic layer
│   ├── db/                       # Database layer
│   └── utils/                    # Utility functions
├── docs/                         # Project documentation
│   ├── architecture/             # Architecture documentation
│   ├── development/              # Development documentation
│   └── api/                      # API documentation
├── migrations/                   # Database migrations
├── logs/                         # Log files
├── docker-compose.yml            # Docker orchestration
├── requirements.txt              # Python dependencies
└── main.py                       # Application entry point
```

### Architecture Features

- **Layered Architecture**: Clear API → Service → Model layering
- **Dependency Injection**: Service layer dependency injection for improved testability
- **Transaction Management**: Unified transaction boundaries in business logic layer
- **Route Registration**: Centralized route management to avoid duplicate configuration
- **Environment Isolation**: Development/production environment configuration separation

## 🚀 Deployment Guide

### Docker Deployment (Recommended)

```bash
# Production environment startup
ENV=production docker-compose up -d

# Scale service instances
docker-compose up -d --scale fastapi-app=3

# Update deployment
docker-compose pull
docker-compose up -d --force-recreate
```

### Traditional Deployment

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Set environment variables
export ENV=production
export POSTGRES_HOST=your-db-host
# ... other environment variables

# 3. Run migrations
alembic upgrade head

# 4. Start service
gunicorn main:app -w 4 -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:8001
```

### Nginx Configuration Example

```nginx
upstream fastapi_backend {
    server 127.0.0.1:8001;
}

server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://fastapi_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Hide documentation access in production (optional)
    location ~ ^/(client|backoffice|api-docs) {
        deny all;
        return 404;
    }
}
```

## 🔧 Development Guide

### Adding New API Endpoints

1. **Create Route File** (`app/api/client/v1/new_module.py`):
```python
from fastapi import APIRouter, Depends
from app.schemas.response import ApiResponse

router = APIRouter()

@router.get("/example")
async def example_endpoint():
    return ApiResponse.success(data={"message": "Hello World"})
```

2. **Register Route** (`app/route/router_registry.py`):
```python
def get_client_routes():
    return [
        # Existing routes...
        RouteConfig("app.api.client.v1.new_module", "/new-module", ["new-module"]),
    ]
```

3. **Update Swagger Configuration** (`app/configs/client_swagger_config.py`):
```python
CLIENT_OPENAPI_TAGS = [
    # Existing tags...
    {
        "name": "new-module",
        "description": "New module endpoints",
        "externalDocs": {
            "description": "Module documentation",
            "url": "https://example.com/docs",
        },
    },
]
```

### Database Operations

```bash
# Create new migration
alembic revision --autogenerate -m "description"

# Apply migrations
alembic upgrade head

# Rollback migration
alembic downgrade -1
```

### Background Tasks

```bash
# Start Celery Worker
celery -A app.core.celery_app worker --loglevel=info

# Start Celery Beat (scheduled tasks)
celery -A app.core.celery_app beat --loglevel=info

# Monitor Celery (optional)
celery -A app.core.celery_app flower
```

## 🧪 Testing

### Running Tests

```bash
# Install test dependencies
pip install pytest pytest-asyncio httpx

# Run all tests
pytest

# Run specific tests
pytest tests/test_api.py

# Generate coverage report
pytest --cov=app tests/
```

### API Testing Example

```python
import pytest
from fastapi.testclient import TestClient
from app.route.route import create_app

@pytest.fixture
def client():
    app = create_app()
    return TestClient(app)

def test_health_check(client):
    response = client.get("/api/v1/config/health")
    assert response.status_code == 200
    assert response.json()["data"]["status"] == "healthy"
```

## 📊 Monitoring and Logging

### Health Checks

System provides multi-level health checks:

- **API Health**: Basic service status
- **Database Health**: PostgreSQL connection status
- **Redis Health**: Cache service status

Access: http://localhost:8001/api/v1/config/health

### Logging System

- **Structured Logging**: JSON format for easy analysis
- **Log Rotation**: Daily rotation with 7-day retention
- **Async Writing**: Redis queue for performance optimization
- **Categorized Storage**: Separate application and SQL logs

Log location: `logs/` directory

### Performance Monitoring

- **Request Response Time**: Automatic API response time recording
- **Error Rate Monitoring**: Real-time error statistics
- **Resource Usage**: Database connection pool status

## 🔒 Security Features

### Authentication and Authorization

- **JWT Authentication**: Secure token authentication mechanism
- **Token Refresh**: Automatic token renewal
- **Permission Control**: Role-based access control

### Security Configuration

- **CORS Control**: Cross-origin resource sharing configuration
- **Data Validation**: Pydantic strict data validation
- **SQL Injection Protection**: SQLAlchemy ORM security protection
- **Environment Isolation**: Sensitive information environment variable management

### Production Security

- **Documentation Hiding**: Production environment automatically hides API documentation
- **Error Handling**: Unified error response format
- **Log Security**: Sensitive information filtering

## 🤝 Contribution Guide

### Development Process

1. Fork project to personal repository
2. Create feature branch: `git checkout -b feature/new-feature`
3. Commit code: `git commit -m 'Add new feature'`
4. Push to branch: `git push origin feature/new-feature`
5. Create Pull Request

### Code Standards

- **Python**: Follow PEP 8 standards
- **Naming Conventions**:
  - Functions and variables: `snake_case`
  - Routes and enums: `kebab-case`
  - Class names: `PascalCase`
- **Type Annotations**: Must add type annotations
- **Docstrings**: Public functions must have documentation

### Commit Standards

- `feat`: New features
- `fix`: Bug fixes
- `docs`: Documentation updates
- `style`: Code formatting adjustments
- `refactor`: Refactoring
- `test`: Test-related
- `chore`: Build or auxiliary tool changes

## 📚 Documentation Links

### Project Documentation

- [Project Architecture Documentation](docs/architecture/project-architecture.md)
- [Development Framework Guide](docs/development/development-framework.md)
- [Swagger Usage Guide](docs/api/swagger-guide.md)
- [Claude Development Guide](CLAUDE.md)

### Related Technical Documentation

- [FastAPI Official Documentation](https://fastapi.tiangolo.com/)
- [SQLAlchemy 2.0 Documentation](https://docs.sqlalchemy.org/en/20/)
- [Celery Documentation](https://docs.celeryproject.org/)
- [Docker Usage Guide](https://docs.docker.com/)
- [PostgreSQL Documentation](https://www.postgresql.org/docs/)

## 📄 License

This project is based on the [MIT License](https://opensource.org/licenses/MIT) open source license.

## 🚨 Frequently Asked Questions

### Q1: Docker container startup failure?
- Check port usage: `lsof -i :8001`
- View container logs: `docker-compose logs fastapi-app`
- Confirm environment variables are configured correctly

### Q2: Database connection failure?
- Check PostgreSQL service status
- Verify database connection parameters
- Confirm network connectivity

### Q3: Swagger documentation inaccessible?
- Confirm service starts on correct port (8001)
- Check environment variable `ENV` setting
- Verify OpenAPI JSON endpoint: `/client/openapi.json`

### Q4: Redis connection error?
- Check Redis service status
- Verify Redis connection parameters
- Confirm firewall settings

### Q5: Celery tasks not executing?
- Confirm Redis as broker is running normally
- Check Celery worker startup status
- View Celery log output

---

📧 **Contact Us**: For questions or suggestions, please contact the development team through Issues or email.

🌟 **Star Support**: If this project helps you, please give us a Star!
