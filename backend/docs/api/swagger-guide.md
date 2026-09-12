# FastAPI Template - Separated Swagger UI Usage Guide

## Overview

The FastAPI Template project now provides separated API documentation, with independent Swagger interfaces and OpenAPI specifications for client API and backoffice management API.

## Access URLs

After starting the project, you can access different API documentation through the following addresses:

### 🌐 Main Entry
- **Unified Entry**: http://localhost:8001/
- **Development Environment**: Shows all available documentation links and access addresses
- **Production Environment**: Hides documentation navigation for enhanced security

### 📱 Client API Documentation
- **Swagger UI**: http://localhost:8001/client/docs
- **ReDoc**: http://localhost:8001/client/redoc
- **OpenAPI JSON**: http://localhost:8001/client/openapi.json

### 🔧 Backoffice Management API Documentation
- **Swagger UI**: http://localhost:8001/backoffice/docs
- **ReDoc**: http://localhost:8001/backoffice/redoc
- **OpenAPI JSON**: http://localhost:8001/backoffice/openapi.json

### 📥 JSON Documentation Export (for API Management Tools)
- **Export Information Page**: http://localhost:8001/api-docs/
- **Client API JSON**: http://localhost:8001/api-docs/client.json
- **Backoffice API JSON**: http://localhost:8001/api-docs/backoffice.json

## Features

### 📝 Separated Documentation
- ✅ Completely independent documentation for client and backoffice APIs
- ✅ Independent interface grouping and descriptions
- ✅ Targeted usage guides and authentication instructions

### 🔒 Environment Security Control
- ✅ Development Environment: Complete documentation navigation and access guidance
- ✅ Production Environment: Hidden documentation navigation to avoid API path exposure
- ✅ Smart Environment Detection: Automatic control based on ENV environment variable

### 🔐 Smart Authentication Configuration
- ✅ Client API: No authentication required, direct testing
- ✅ Backoffice API: Automatic JWT authentication configuration, only need to login once

### 📤 Multi-format Export
- ✅ OpenAPI 3.0.2 standard format
- ✅ Support for importing into Postman, Insomnia, ApiPost, Apifox and other tools
- ✅ One-click JSON document download

## Usage Instructions

### 1. Start Service
```bash
# Enter project directory
cd /Users/skybao/Python/fastapi-template

# Activate virtual environment
source venv/bin/activate

# Install dependencies (if needed)
pip install -r requirements.txt

# Start development server (note port is 8001)
python main.py
```

### 2. Access Documentation Homepage
Open browser and visit: http://localhost:8001/

You will see all available documentation links.

### 3. Test Client API

#### Direct Access to Client Documentation
1. Visit: http://localhost:8001/client/docs
2. No authentication required, test all client interfaces directly
3. Included interface modules:
   - **client-demo**: Demo interfaces
   - **client-config**: Configuration interfaces
   - **client-aws**: AWS S3 storage interfaces

### 4. Test Backoffice Management API

#### Access Backoffice Documentation
1. Visit: http://localhost:8001/backoffice/docs
2. Included interface modules:
   - **backoffice-auth**: Authentication management
   - **backoffice-admin**: Administrator management
   - **backoffice-aws**: AWS management interfaces

#### JWT Authentication Setup
1. **Get Token**:
   - Find the `backoffice-auth` group
   - Click `/api/v1/backoffice/auth/login`
   - Enter login information and execute
   - Copy the returned `access_token`

2. **Set Authentication**:
   - Click the 🔒 **Authorize** button in the top right corner
   - In the `BearerAuth` input box, enter: `Bearer your-token`
   - Click **Authorize**
   - Click **Close**

3. **Test Authenticated Interfaces**:
   - Now all interfaces requiring authentication will automatically carry the auth header
   - Except for the `/login` interface, all other backoffice interfaces require authentication

### 5. Export API Documentation to Management Tools

#### Get OpenAPI JSON Documentation
1. **View Export Instructions**: http://localhost:8001/api-docs/
2. **Download Client API**: http://localhost:8001/api-docs/client.json
3. **Download Backoffice API**: http://localhost:8001/api-docs/backoffice.json

#### Import to Common Tools

**Postman Import**:
1. Open Postman
2. Click **Import** button
3. Select **Upload Files**
4. Select downloaded JSON file
5. Click **Import**

**Insomnia Import**:
1. Open Insomnia
2. Select **Import/Export** > **Import Data**
3. Select downloaded JSON file
4. Click **Scan** then **Import**

**ApiPost Import**:
1. Open ApiPost
2. Select **Import** > **OpenAPI**
3. Select downloaded JSON file
4. Complete import

**Apifox Import**:
1. Open Apifox
2. Select **Import** > **Import from URL/File**
3. Select **OpenAPI Format**
4. Select downloaded JSON file
5. Complete import

## Interface Group Descriptions

### Client API (Client)

#### client-demo
- Demo function interfaces
- No authentication required
- Used for function testing and demonstration

#### client-config
- Client configuration related interfaces
- No authentication required
- Get system configuration information

#### client-aws
- AWS S3 upload functionality
- No authentication required
- File upload and cloud storage operations

### Backoffice Management API (Backoffice)

#### backoffice-auth
- **Login** (`/login`) - No authentication required
- **Refresh Token** (`/refresh`) - Authentication required
- **Logout** (`/logout`) - Authentication required

#### backoffice-admin
- Administrator account management
- All require JWT authentication
- CRUD operation interfaces
- Password management functions

#### backoffice-aws
- AWS S3 management interfaces
- Require JWT authentication
- File management and permission control

## Environment Control

### Development Environment (ENV=development)
- **Complete Navigation**: Root path displays full API documentation navigation
- **All Features Available**: All documentation endpoints accessible
- **Development-Friendly**: Easy access to all API testing features

### Production Environment (ENV=production)
- **Hidden Navigation**: Root path doesn't display documentation navigation
- **Security Enhancement**: Prevents exposure of internal API structure
- **Direct Access**: Documentation still accessible via direct URLs (require domain control)

### Preview Environment (ENV=preview)
- **Same as Development**: Full documentation access for testing
- **Pre-production Testing**: Safe environment for final testing

## Technical Architecture

### Separated Documentation Applications
- **Design Principle**: Each API domain has independent FastAPI application
- **Advantages**: Independent configuration, security isolation, documentation customization
- **Implementation**: Mounted to main application via `mount` method

### Route Registration System
- **Unified Management**: Use route registration center for unified management
- **Avoid Duplication**: Main application and documentation applications share route configuration
- **Dynamic Loading**: Runtime dynamic loading of route configurations

### Security Considerations
- **Environment Isolation**: Production environment hides documentation navigation
- **Authentication Control**: Backoffice API enforces JWT authentication
- **Access Control**: Control access through CORS and environment variables

## Troubleshooting

### Common Issues

#### 1. 404 Error
- **Problem**: Accessing documentation URL returns 404
- **Cause**: May be in production environment or route configuration error
- **Solution**: Check environment variable `ENV` setting

#### 2. Authentication Failure
- **Problem**: Backoffice API cannot authenticate
- **Cause**: JWT token format error or expired
- **Solution**: Re-obtain token, check format

#### 3. CORS Error
- **Problem**: Cross-origin access blocked
- **Cause**: CORS configuration restrictions
- **Solution**: Check `ALLOWED_ORIGINS` configuration

### Debugging Methods

#### Check Service Status
```bash
# Check application health status
curl http://localhost:8001/api/v1/config/health

# Check environment information (development environment only)
curl http://localhost:8001/
```

#### Verify Route Configuration
```bash
# Check available routes
curl -s http://localhost:8001/client/openapi.json | jq '.paths | keys'
```

#### Test Authentication
```bash
# Get authentication token (requires valid credentials)
curl -X POST http://localhost:8001/api/v1/backoffice/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"password"}'
```

## Frequently Asked Questions

### Q1: Why separate documentation?
- ✅ **Responsibility Separation**: Client and backoffice APIs serve different user groups
- ✅ **Permission Isolation**: Prevent client developers from seeing sensitive backoffice interfaces
- ✅ **Clear Documentation**: Each documentation only shows relevant interfaces, improving readability
- ✅ **Import Convenience**: Can be imported to different API management tools separately

### Q2: What to do about missing dependencies?
```bash
# Install project dependencies
pip install -r requirements.txt

# If specific package is missing
pip install bleach  # Example
```

### Q3: Authentication configuration not working?
- Confirm accessing backoffice documentation address: `/backoffice/docs`
- Check token format: Must include "Bearer " prefix
- Confirm token not expired
- Try re-login to get new token

### Q4: Cannot access documentation?
- Confirm service started on correct port (default 8001)
- Check firewall settings
- Confirm virtual environment activated
- Check logs for error information

### Q5: What are JSON export files used for?
- **API Testing Tools**: Postman, Insomnia, ApiPost, Apifox, etc.
- **Code Generation**: Generate SDKs in various languages
- **Documentation Generation**: Generate API documentation in other formats
- **API Gateway**: Import to API gateway for management

### Q6: How to access documentation in production environment?
- **Root Navigation**: Production environment root path doesn't display documentation navigation
- **Direct Access**: Still accessible via complete URLs
- **Security Control**: Recommend controlling documentation access at Nginx/gateway level
- **Environment Variables**: Control through `ENV=production` to hide root navigation

## Technical Features

### FastAPI Template Special Features
- 🔒 **JWT Authentication**: Complete user authentication and permission management
- ☁️ **AWS Integration**: S3 file upload and management functionality
- 📧 **Email System**: Support for multiple email service providers
- 🎯 **Cache System**: Redis cache optimizes performance
- 📊 **Database**: PostgreSQL async operations
- ⚡ **Async Tasks**: Celery background task processing

### Separated Documentation Advantages
- 📱 **Client Specific**: Show public APIs without authentication complexity
- 🔧 **Backoffice Specific**: Complete management functions with authentication configuration
- 📤 **Export Friendly**: JSON format supports various API tools
- 🎯 **Development Convenience**: Clear division of labor, efficient testing

---

📚 **Related Links**:
- [FastAPI Official Documentation](https://fastapi.tiangolo.com/)
- [OpenAPI Specification](https://swagger.io/specification/)
- [Swagger UI Documentation](https://swagger.io/tools/swagger-ui/)