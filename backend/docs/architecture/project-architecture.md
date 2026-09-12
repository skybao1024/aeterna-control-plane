# FastAPI Template Project Architecture Documentation

## Overview

FastAPI Template is a modern Web API template project based on the FastAPI framework, adopting async architecture design to support high-concurrency and high-performance Web service development.

## Core Architecture Features

### Dual-Client Architecture Pattern
- **Client API** (`/api/v1/`): Public interfaces for client applications
- **Backoffice API** (`/api/v1/backoffice/`): Authenticated interfaces for management side

### Technology Stack
- **Web Framework**: FastAPI 0.136.1
- **Database**: PostgreSQL (async asyncpg + psycopg2-binary)
- **ORM**: SQLAlchemy 2.0.49 (async)
- **Cache/Message Queue**: Redis 6.4.0 client / Redis 7+ server
- **Background Tasks**: Celery 5.6.3
- **Data Validation**: Pydantic 2.13.4
- **Authentication**: JWT (python-jose 3.5.0)
- **File Storage**: AWS S3 (boto3 1.43.11)
- **Email Service**: SMTP / Brevo API

## Project Directory Structure

```
fastapi-template/
├── app/                          # Main application directory
│   ├── api/                      # API routing layer
│   │   ├── client/v1/            # Client API v1
│   │   ├── backoffice/v1/        # Backoffice management API v1
│   │   └── docs_export.py        # API documentation export
│   ├── core/                     # Core system configuration
│   │   ├── config.py             # Environment configuration
│   │   ├── celery_app.py         # Celery configuration
│   │   ├── log_config.py         # Logging configuration
│   │   └── security.py           # Security configuration
│   ├── configs/                  # Application configuration definitions
│   │   ├── client_swagger_config.py    # Client Swagger configuration
│   │   ├── backoffice_swagger_config.py # Backoffice Swagger configuration
│   │   └── docs_apps.py          # Documentation application configuration
│   ├── route/                    # Route management
│   │   ├── route.py              # Main route configuration
│   │   └── router_registry.py    # Route registration center
│   ├── db/                       # Database layer
│   │   ├── base.py               # Database connection (lazy loading)
│   │   ├── session.py            # Session management
│   │   └── models.py             # Base models
│   ├── models/                   # Data models
│   │   ├── user.py               # User model
│   │   ├── admin.py              # Admin model
│   │   └── base.py               # Base model class
│   ├── schemas/                  # Pydantic schemas
│   │   ├── client/               # Client schemas
│   │   ├── backoffice/           # Backoffice schemas
│   │   └── response.py           # Unified response format
│   ├── services/                 # Business logic layer
│   │   ├── client/               # Client services
│   │   ├── backoffice/           # Backoffice services
│   │   └── common/               # Common services
│   ├── schedule/                 # Scheduled tasks
│   │   ├── jobs/                 # Task definitions
│   │   └── celery_job.py         # Celery tasks
│   ├── common/                   # Common components
│   │   └── log_consumer.py       # Log consumer
│   ├── utils/                    # Utility functions
│   └── exceptions/               # Exception handling
├── migrations/                   # Alembic database migrations
├── logs/                         # Log files
├── docs/                         # Project documentation
├── shell/                        # Temporary scripts directory
├── docker-compose.yml            # Docker orchestration configuration
├── docker-compose.dev.yml        # Development environment configuration
├── Dockerfile                    # Container image configuration
├── requirements.txt              # Python dependencies
├── main.py                       # Application entry point
└── CLAUDE.md                     # Claude development guide
```

## Architecture Layers

### 1. Routing Layer (API Layer)
- **Path**: `app/api/`
- **Responsibility**: HTTP request handling, parameter validation, response formatting
- **Features**: Versioned API (v1), dual-client support

### 2. Business Logic Layer (Service Layer)
- **Path**: `app/services/`
- **Responsibility**: Business logic processing, data transformation, transaction management
- **Features**: Dependency injection, transaction boundary management

### 3. Data Access Layer (Data Layer)
- **Path**: `app/models/`, `app/db/`
- **Responsibility**: Data model definition, database operations
- **Features**: Async ORM, lazy loading engine, connection pool optimization

### 4. Configuration Layer (Core Layer)
- **Path**: `app/core/`
- **Responsibility**: Application configuration, security settings, third-party service configuration
- **Features**: Environment variable configuration, type safety

## Core Design Principles

### 1. Dependency Injection Pattern
```python
# Route layer uses dependency injection to get services
@router.post("/example")
async def example_handler(
    service: ExampleService = Depends(get_example_service),
    db: AsyncSession = Depends(get_db)
):
    result = await service.process_data(db)
    return ApiResponse.success(data=result)
```

### 2. Transaction Boundary Management
```python
# Business logic layer manages transactions
async def process_data(self, db: AsyncSession):
    async with transaction(db):
        # Business logic here
        pass
```

### 3. Lazy Loading Database Engine
```python
# Avoid Alembic migration import issues
def get_engine():
    global engine
    if engine is None:
        engine = create_async_engine(...)
    return engine
```

### 4. Unified Response Format
```python
# All APIs use unified response format
return ApiResponse.success(data=result)
return ApiResponse.failed(message="Error message", body_code=400)
```

## Database Architecture

### PostgreSQL Dual Driver Architecture
- **asyncpg**: High-performance async operations for application runtime
- **psycopg2-binary**: Sync operations for Alembic migrations

### Connection Pool Configuration
- **Production Environment**: 20 connection pool, 10 overflow, 30-minute recycle
- **Scheduled Tasks**: 5 connection pool, independent engine

### Time Field Standards
- Unified use of `TIMESTAMPTZ` type
- Automatic timezone awareness and conversion

## Cache and Message Queue

### Redis Architecture
- **Cache**: Application data cache
- **Message Queue**: Celery task queue
- **Log Aggregation**: Structured log collection

### Celery Task System
- **Worker**: Background task execution
- **Beat**: Scheduled task scheduling
- **Flower**: Monitoring dashboard (optional)

## Security Architecture

### JWT Authentication
- **Access Token**: 30-minute expiration
- **Refresh Token**: 7-day expiration
- **Algorithm**: HS256

### API Security
- **CORS Configuration**: Cross-origin resource sharing control
- **Request Validation**: Pydantic data validation
- **Exception Handling**: Unified exception response format

## Logging Architecture

### Structured Logging
- **File Rotation**: Daily split, 7-day retention
- **Async Consumption**: Redis queue async writing
- **Categorized Storage**: Separate application and SQL logs

### Monitoring Metrics
- **Health Checks**: `/api/v1/config/health`
- **Performance Monitoring**: Request response time, error rate
- **Resource Monitoring**: Database connection, Redis connection status

## Containerization Architecture

### Docker Services
- **fastapi-app**: Main application service
- **redis**: Cache and message queue
- **celery-worker**: Background task processing
- **celery-beat**: Scheduled task scheduling
- **nginx**: Reverse proxy (optional)

### Network Architecture
- **Internal Network**: Inter-container communication using service names
- **Port Mapping**: External access through port mapping
- **Health Checks**: Application-level health status monitoring

## Scalability Design

### Horizontal Scaling
- **Stateless Design**: Application services can scale horizontally
- **Session Storage**: Redis centralized session management
- **Load Balancing**: Nginx reverse proxy support

### Modular Scaling
- **Versioned API**: Support for multiple version coexistence
- **Plugin Services**: Modular service layer design
- **Configuration Management**: Unified environment variable configuration

## Performance Optimization

### Database Optimization
- **Connection Pool**: Pre-configured connection pool size
- **Query Optimization**: Async queries and batch operations
- **Index Strategy**: Index design based on business query patterns

### Caching Strategy
- **Data Cache**: Hot data Redis cache
- **Query Cache**: Complex query result cache
- **Session Cache**: User session information cache

### Async Processing
- **Async I/O**: Full async database and network operations
- **Background Tasks**: Long-running task async processing
- **Event-Driven**: Event-based async architecture

## Development and Deployment

### Development Environment
- **Hot Reload**: Automatic reload on code changes
- **Container Development**: Docker unified development environment
- **Debug Support**: Complete error stack and logging

### Production Deployment
- **Container Deployment**: Docker Compose production configuration
- **Environment Isolation**: Development/production environment configuration separation
- **Automated Deployment**: CI/CD pipeline support

This architecture design ensures project maintainability, scalability, and high performance while providing complete development and operations support.
