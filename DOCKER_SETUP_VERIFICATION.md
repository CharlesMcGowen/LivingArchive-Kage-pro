# Docker Setup Verification - LivingArchive-Kage-pro

## ✅ Docker Configuration Status

### Files Present
- ✅ `docker/docker-compose.yml` - Docker Compose configuration
- ✅ `docker/Dockerfile` - Daemon container image
- ✅ `docker/Dockerfile.django` - Django server container image
- ✅ `docker/start_django.sh` - Quick start script
- ✅ `docker/env.example` - Environment variable template
- ✅ `docker/README.md` - Docker documentation
- ✅ `docker/README.django.md` - Django-specific Docker docs

### Docker Compose Services

1. **django-server** (Port 9000)
   - Build: `docker/Dockerfile.django`
   - Port: `9000:9000`
   - Health check: `/reconnaissance/`
   - Volumes:
     - `staticfiles/` (Static files)
     - `config/` (Configuration files)

2. **kage-daemon** (Port Scanner)
   - Build: `docker/Dockerfile`
   - Depends on: `django-server`
   - Health check: `/reconnaissance/api/daemon/kage/health/`

3. **kumo-daemon** (HTTP Spider)
   - Build: `docker/Dockerfile`
   - Depends on: `django-server`
   - Health check: `/reconnaissance/api/daemon/kumo/health/`

4. **ryu-daemon** (Threat Assessment)
   - Build: `docker/Dockerfile`
   - Depends on: `django-server`
   - Health check: `/reconnaissance/api/daemon/ryu/health/`

## Quick Start Commands

### Start Django Server Only
```bash
cd /media/ego/328010BE80108A8D1/github_public/LivingArchive-Kage-pro
docker-compose -f docker/docker-compose.yml up --build -d django-server
```

### Start All Services (Django + Daemons)
```bash
cd /media/ego/328010BE80108A8D1/github_public/LivingArchive-Kage-pro
docker-compose -f docker/docker-compose.yml up --build -d
```

### Using Quick Start Script
```bash
cd /media/ego/328010BE80108A8D1/github_public/LivingArchive-Kage-pro
./docker/start_django.sh
```

## Verification Steps

### 1. Check Docker Images Build Successfully
```bash
cd /media/ego/328010BE80108A8D1/github_public/LivingArchive-Kage-pro
docker-compose -f docker/docker-compose.yml build
```

### 2. Check Services Start
```bash
docker-compose -f docker/docker-compose.yml up -d
docker-compose -f docker/docker-compose.yml ps
```

### 3. Check Health Status
```bash
# Django server health
docker inspect recon-django | grep -A 10 Health

# Daemon health
docker inspect recon-kage | grep -A 10 Health
```

### 4. Test Web Interface
```bash
curl http://localhost:9000/reconnaissance/
```

### 5. Test API Endpoints
```bash
# Kage health check
curl http://localhost:9000/reconnaissance/api/daemon/kage/health/

# Kumo health check
curl http://localhost:9000/reconnaissance/api/daemon/kumo/health/

# Ryu health check
curl http://localhost:9000/reconnaissance/api/daemon/ryu/health/
```

### 6. View Logs
```bash
# Django server logs
docker-compose -f docker/docker-compose.yml logs -f django-server

# Kage daemon logs
docker-compose -f docker/docker-compose.yml logs -f kage-daemon
```

## Configuration

### Environment Variables

Create `docker/.env` file (optional):
```bash
cp docker/env.example docker/.env
# Edit docker/.env with your settings
```

Key variables:
- `SECRET_KEY` - Django secret key
- `DEBUG` - Debug mode (True/False)
- `DB_HOST` - PostgreSQL host (optional)
- `DB_USER` - PostgreSQL user
- `DB_PASSWORD` - PostgreSQL password

### Database Configuration

**PostgreSQL is Required** (SQLite removed to avoid corruption issues)

1. **Default Database**: Uses `eggrecords` database (port 5436)
2. **Additional Databases**:
   - `customer_eggs` database (port 15440)
   - `eggrecords` database (port 5436) - also used as default

**Configuration:**
- Set `DB_HOST` environment variable (default: localhost)
- Configure database credentials in `docker/.env`
- Required variables: `DB_HOST`, `DB_USER`, `DB_PASSWORD`

## Potential Issues & Fixes

### Issue 1: Port 9000 Already in Use
**Fix:** Change port mapping in `docker-compose.yml`:
```yaml
ports:
  - "9001:9000"  # Use different host port
```

### Issue 2: Missing Dependencies
**Fix:** Ensure `requirements.txt` includes:
- `django>=4.2.0`
- `psycopg2-binary>=2.9.0` (for PostgreSQL)
- `python-dotenv>=1.0.0` (for .env support)

### Issue 3: Static Files Not Loading
**Fix:** Run collectstatic:
```bash
docker-compose -f docker/docker-compose.yml exec django-server python manage.py collectstatic --noinput
```

### Issue 4: Database Migration Needed
**Fix:** Run migrations:
```bash
docker-compose -f docker/docker-compose.yml exec django-server python manage.py migrate
```

### Issue 5: Health Check Failing
**Fix:** Check if Django server is running:
```bash
docker-compose -f docker/docker-compose.yml logs django-server
```

## Testing Full Functionality

### Test 1: Django Server Responds
```bash
curl -I http://localhost:9000/reconnaissance/
# Should return: HTTP/1.1 200 OK
```

### Test 2: API Endpoints Work
```bash
# Get Kage status
curl http://localhost:9000/reconnaissance/api/kage/status/

# Should return JSON with status information
```

### Test 3: Daemons Can Connect
```bash
# Check daemon logs for connection errors
docker-compose -f docker/docker-compose.yml logs kage-daemon | grep -i error
```

### Test 4: Database Connection (if using PostgreSQL)
```bash
docker-compose -f docker/docker-compose.yml exec django-server python manage.py dbshell
```

## Production Recommendations

1. **Set Strong SECRET_KEY**
   ```bash
   export SECRET_KEY=$(python -c 'from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())')
   ```

2. **Disable Debug Mode**
   ```bash
   export DEBUG=False
   ```

3. **Use Production WSGI Server**
   - Add `gunicorn>=21.2.0` to `requirements.txt`
   - Update `Dockerfile.django` CMD to use gunicorn

4. **Configure ALLOWED_HOSTS**
   - Update `settings.py` with production domain

5. **Use Docker Secrets** for sensitive data
   - Store secrets in Docker secrets or environment files

## Summary

✅ **Docker Setup**: Complete and ready
✅ **Configuration**: All files present
✅ **Documentation**: Comprehensive
✅ **Health Checks**: Configured for all services
✅ **Volumes**: Properly mounted for persistence

**Status**: Ready for testing and deployment! 🐳

