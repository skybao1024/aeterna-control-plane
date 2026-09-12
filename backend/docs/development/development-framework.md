# FastAPI Template Development Framework Guide

## Development Environment Requirements

### Basic Environment
- **Python**: 3.14+
- **PostgreSQL**: 13+
- **Redis**: 7+
- **Docker**: 20.10+
- **Docker Compose**: 2.0+

### Recommended Development Tools
- **IDE**: VS Code / PyCharm
- **API Testing**: Postman / Insomnia
- **Database Management**: pgAdmin / DBeaver
- **Redis Management**: RedisInsight

## Project Initialization

### 1. Virtual Environment Setup

```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# Linux/Mac
source venv/bin/activate
# Windows
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Environment Configuration

```bash
# Copy environment file
cp .env.example .env

# Edit environment variables
vim .env
```

Essential configurations:
```env
ENV=development
POSTGRES_HOST=localhost
POSTGRES_USER=demo
POSTGRES_PASSWORD=demo123
POSTGRES_DB=demo
REDIS_HOST=redis
REDIS_PORT=6379
SECRET_KEY=your-secret-key
```

### 3. Database Initialization

```bash
# Start PostgreSQL (using Docker)
docker run -d --name postgres-dev \
  -e POSTGRES_USER=demo \
  -e POSTGRES_PASSWORD=demo123 \
  -e POSTGRES_DB=demo \
  -p 5432:5432 postgres:15

# Run database migrations
alembic upgrade head
```

### 4. Start Development Server

```bash
# Start development server
python main.py

# Or use uvicorn directly
uvicorn main:app --reload --host 0.0.0.0 --port 8001
```

## Development Workflow

### Code Structure Guidelines

#### 1. API Route Development

**File Location**: `app/api/{client|backoffice}/v1/`

```python
# Example: app/api/client/v1/users.py
from fastapi import APIRouter, Depends
from app.schemas.response import ApiResponse
from app.services.client.user_service import UserService

router = APIRouter()

@router.get("/users")
async def get_users(
    service: UserService = Depends(get_user_service)
):
    users = await service.get_all_users()
    return ApiResponse.success(data=users)
```

#### 2. Service Layer Development

**File Location**: `app/services/{client|backoffice}/`

```python
# Example: app/services/client/user_service.py
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.user import User

class UserService:
    async def get_all_users(self, db: AsyncSession):
        # Business logic implementation
        result = await db.execute(select(User))
        return result.scalars().all()
```

#### 3. Data Model Development

**File Location**: `app/models/`

```python
# Example: app/models/user.py
from sqlalchemy import Column, Integer, String, DateTime
from app.models.base import BaseModel

class User(BaseModel):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    email = Column(String(100), unique=True, nullable=False)
    created_at = Column(DateTime, nullable=False)
```

#### 4. Schema Definition

**File Location**: `app/schemas/{client|backoffice}/`

```python
# Example: app/schemas/client/user.py
from pydantic import BaseModel, EmailStr
from datetime import datetime

class UserCreate(BaseModel):
    username: str
    email: EmailStr

class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    created_at: datetime

    class Config:
        from_attributes = True
```

### Route Registration

#### 1. Add Route to Registry

**File**: `app/route/router_registry.py`

```python
def get_client_routes():
    return [
        RouteConfig("app.api.client.v1.demo", "/demo", ["client-demo"]),
        RouteConfig("app.api.client.v1.users", "/users", ["client-users"]),  # New route
        # ... other routes
    ]
```

#### 2. Update Swagger Configuration

**File**: `app/configs/client_swagger_config.py`

```python
CLIENT_OPENAPI_TAGS = [
    {
        "name": "client-users",
        "description": "User management endpoints",
        "externalDocs": {
            "description": "User API documentation",
            "url": "https://fastapi.tiangolo.com/tutorial/",
        },
    },
    # ... other tags
]
```

## Database Operations

### Migration Management

```bash
# Create new migration
alembic revision --autogenerate -m "add user table"

# Apply migrations
alembic upgrade head

# Rollback migration
alembic downgrade -1

# View migration history
alembic history

# View current revision
alembic current
```

### Database Session Management

```python
# In service layer
from app.db.session import get_db

async def create_user(self, user_data: UserCreate, db: AsyncSession):
    async with transaction(db):
        user = User(**user_data.dict())
        db.add(user)
        await db.commit()
        await db.refresh(user)
        return user
```

## Testing

### Unit Testing

**File Location**: `tests/`

```python
# Example: tests/test_user_service.py
import pytest
from app.services.client.user_service import UserService

@pytest.mark.asyncio
async def test_create_user():
    service = UserService()
    user_data = {"username": "test", "email": "test@example.com"}

    user = await service.create_user(user_data)
    assert user.username == "test"
```

### API Testing

```python
# Example: tests/test_user_api.py
from fastapi.testclient import TestClient
from app.route.route import create_app

def test_get_users():
    app = create_app()
    client = TestClient(app)

    response = client.get("/api/v1/users")
    assert response.status_code == 200
```

### Running Tests

```bash
# Install test dependencies
pip install pytest pytest-asyncio httpx

# Run all tests
pytest

# Run with coverage
pytest --cov=app tests/

# Run specific test file
pytest tests/test_user_api.py
```

## Background Tasks

### Celery Task Development

**File Location**: `app/schedule/jobs/`

```python
# Example: app/schedule/jobs/email_tasks.py
from celery import shared_task

@shared_task
def send_welcome_email(user_email: str):
    # Email sending logic
    print(f"Sending welcome email to {user_email}")
    return f"Email sent to {user_email}"
```

### Starting Background Services

```bash
# Start Celery worker
celery -A app.core.celery_app worker --loglevel=info

# Start Celery beat (scheduler)
celery -A app.core.celery_app beat --loglevel=info

# Monitor with Flower
celery -A app.core.celery_app flower
```

## Development Best Practices

### Code Style

1. **Follow PEP 8** standards
2. **Use type hints** for all functions
3. **Add docstrings** for public methods
4. **Use meaningful variable names**

```python
# Good example
async def get_user_by_id(user_id: int, db: AsyncSession) -> Optional[User]:
    """
    Retrieve a user by their ID.

    Args:
        user_id: The unique identifier for the user
        db: Database session

    Returns:
        User object if found, None otherwise
    """
    result = await db.execute(select(User).where(User.id == user_id))
    return result.scalar_one_or_none()
```

### Error Handling

```python
from app.exceptions.http_exceptions import APIException

async def get_user_by_id(user_id: int, db: AsyncSession) -> User:
    user = await db.get(User, user_id)
    if not user:
        raise APIException(
            status_code=404,
            code=404001,
            detail="User not found"
        )
    return user
```

### Logging

```python
import logging

logger = logging.getLogger(__name__)

async def process_user_data(user_data: dict):
    logger.info(f"Processing user data for {user_data.get('username')}")
    try:
        # Process data
        pass
    except Exception as e:
        logger.error(f"Error processing user data: {e}")
        raise
```

## Docker Development

### Development with Docker Compose

```bash
# Start all services
docker-compose -f docker-compose.dev.yml up -d

# View logs
docker-compose logs -f fastapi-app

# Access application container
docker-compose exec fastapi-app bash

# Rebuild containers
docker-compose up -d --build
```

### Container Development

```dockerfile
# Development Dockerfile example
FROM python:3.14.5-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install -r requirements.txt

# Copy application code
COPY . .

# Start development server
CMD ["python", "main.py"]
```

## API Documentation

### Accessing Documentation

Development environment URLs:
- **Root Navigation**: http://localhost:8001/
- **Client API Docs**: http://localhost:8001/client/docs
- **Backoffice API Docs**: http://localhost:8001/backoffice/docs

### Customizing Documentation

Edit Swagger configurations:
- **Client API**: `app/configs/client_swagger_config.py`
- **Backoffice API**: `app/configs/backoffice_swagger_config.py`

## Performance Monitoring

### Health Checks

Monitor application health:
```bash
curl http://localhost:8001/api/v1/config/health
```

### Log Monitoring

View application logs:
```bash
# View container logs
docker-compose logs -f fastapi-app

# View log files
tail -f logs/app.log
```

## Debugging

### Development Debugging

1. **Use IDE debugger** with breakpoints
2. **Add print statements** for quick debugging
3. **Check logs** in `logs/` directory
4. **Use Swagger UI** for API testing

### Common Issues

#### Database Connection Issues
```bash
# Check PostgreSQL status
docker ps | grep postgres

# Check connection
psql -h localhost -U demo -d demo
```

#### Redis Connection Issues
```bash
# Check Redis status
docker ps | grep redis

# Test Redis connection
redis-cli -h localhost -p 6379 ping
```

## Deployment Preparation

### Production Checklist

1. **Environment Variables**: Set production values
2. **Database**: Run migrations
3. **Static Files**: Collect and optimize
4. **Dependencies**: Lock versions in requirements.txt
5. **Security**: Review security settings
6. **Performance**: Optimize for production

### Environment-Specific Configurations

```python
# app/core/config.py
class Settings(BaseSettings):
    ENV: str = "development"

    @property
    def is_production(self) -> bool:
        return self.ENV == "production"

    @property
    def log_level(self) -> str:
        return "INFO" if self.is_production else "DEBUG"
```

This development framework guide provides a comprehensive foundation for developing with the FastAPI Template project.
