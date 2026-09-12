# Docker部署文档

## 项目Docker化部署指南

### 概述

本项目使用Docker Compose进行容器化部署，包含以下服务：
- **app**: FastAPI应用主服务
- **nginx**: 反向代理服务器
- **redis**: 缓存和消息队列
- **celery-worker**: 后台任务处理
- **celery-beat**: 定时任务调度
- **flower**: Celery监控面板（可选）

数据库使用AWS RDS，无需在Docker中部署。

### 部署前准备

#### 1. 环境配置

复制环境变量模板并配置：
```bash
cp .env.example .env
```

编辑`.env`文件，重点配置：
- **数据库**: 配置RDS连接信息
- **Redis**: 使用默认配置（容器内Redis）
- **JWT**: 修改`SECRET_KEY`为强密码
- **AWS S3**: 配置文件存储
- **Email**: 配置邮件服务

#### 2. 数据库迁移

确保RDS数据库已创建，然后运行迁移：
```bash
# 本地运行迁移（需要先激活虚拟环境）
source venv/bin/activate && alembic upgrade head
```

### 部署命令

#### 开发环境部署（使用覆盖文件，不使用Nginx）
```bash
# 使用专用的开发环境配置文件
docker-compose -f docker-compose.yml -f docker-compose.dev.yml up -d

# 查看服务状态
docker-compose -f docker-compose.yml -f docker-compose.dev.yml ps

# 查看日志
docker-compose -f docker-compose.yml -f docker-compose.dev.yml logs -f

# 开发环境直接访问FastAPI应用
# API文档: http://localhost:8001/docs
# API根路径: http://localhost:8001/api/v1/
# 健康检查: http://localhost:8001/api/v1/config/health
```

#### 生产环境部署（使用Nginx反向代理）
```bash
# 启动包含Nginx反向代理的完整生产环境服务
docker-compose up -d

# 启动包含Nginx和Flower监控的完整生产环境服务
docker-compose --profile monitoring up -d
```

#### 其他常用命令
```bash
# 重新构建镜像
docker-compose build

# 仅启动特定服务
docker-compose up -d app nginx redis

# 停止所有服务
docker-compose down

# 停止并删除数据卷
docker-compose down -ve

# 查看资源使用情况
docker-compose top
```

### 服务访问

#### 开发环境（使用docker-compose.dev.yml覆盖文件）
```bash
docker-compose -f docker-compose.yml -f docker-compose.dev.yml up -d
```
- **API文档**: http://localhost:8001/docs
- **API根路径**: http://localhost:8001/api/v1/
- **健康检查**: http://localhost:8001/api/v1/config/health
- **Flower监控**: http://localhost:5555 (仅在监控模式下)
- **Redis**: localhost:6380

#### 生产环境（默认配置，包含Nginx反向代理）
```bash
docker-compose up -d
```
- **API文档**: http://localhost:8080/docs
- **API根路径**: http://localhost:8080/api/v1/
- **健康检查**: http://localhost:8080/health
- **Flower监控**: http://localhost:5555 (仅在监控模式下)
- **Redis**: localhost:6380

### 服务说明

#### FastAPI应用 (app)
- 端口：内部8001
- 健康检查：`/api/v1/config/health`
- 日志：`./logs`目录挂载

在开发环境中，应用端口直接暴露为8001
在生产环境中，应用通过Nginx反向代理访问

#### Nginx反向代理（默认启用）
- 端口：8080（HTTP）、8443（HTTPS可选）
- 配置文件：`./nginx/nginx.conf`
- 功能：反向代理、Gzip压缩、静态文件缓存
- 启动方式：默认随docker-compose up -d启动

#### Redis缓存
- 端口：6379
- 数据持久化：Docker卷`redis-data`
- 用途：缓存和Celery消息队列

#### Celery服务
- **Worker**: 处理后台任务
- **Beat**: 定时任务调度
- **Flower**: Web监控界面（可选）

### 健康检查

所有服务都配置了健康检查：
```bash
# 检查所有服务健康状态
docker-compose ps

# 查看具体服务健康状态
docker inspect --format='{{.State.Health.Status}}' fastapi-app
```

### 日志管理

```bash
# 查看所有服务日志
docker-compose logs

# 查看特定服务日志
docker-compose logs app
docker-compose logs nginx

# 实时跟踪日志
docker-compose logs -f --tail=100

# 应用日志文件位置
ls -la ./logs/
```

### 故障排除

#### 常见问题

1. **数据库连接失败**
   - 检查RDS配置和网络连接
   - 确认数据库用户权限

2. **Redis连接失败**
   - 检查Redis容器状态：`docker-compose ps redis`
   - 检查密码配置

3. **Nginx代理失败**
   - 检查app服务是否正常：`docker-compose ps app`
   - 查看nginx日志：`docker-compose logs nginx`

4. **Celery任务不执行**
   - 检查worker状态：`docker-compose ps celery-worker`
   - 查看worker日志：`docker-compose logs celery-worker`

#### 调试命令

```bash
# 进入容器调试
docker-compose exec app bash
docker-compose exec nginx sh

# 查看容器资源使用
docker stats

# 重启特定服务
docker-compose restart app
```

### 生产环境优化

1. **安全配置**
   - 修改默认密码
   - 配置HTTPS（SSL证书放在`./ssl`目录）
   - 限制不必要的端口暴露

2. **性能优化**
   - 调整worker数量
   - 配置Redis持久化策略
   - 启用Nginx缓存

3. **监控告警**
   - 使用Flower监控Celery
   - 配置日志收集
   - 设置健康检查告警

### 更新部署

```bash
# 更新代码后重新部署
git pull
docker-compose build
docker-compose up -d

# 仅重启应用服务（不重启Redis等）
docker-compose restart app celery-worker celery-beat
```

### 备份与恢复

```bash
# 备份Redis数据
docker-compose exec redis redis-cli --rdb /data/backup.rdb

# 备份应用日志
tar -czf logs-backup-$(date +%Y%m%d).tar.gz logs/

# 数据库备份（RDS需单独处理）
# 参考AWS RDS备份文档
```