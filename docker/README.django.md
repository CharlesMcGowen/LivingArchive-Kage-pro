# Django Server Containerization

This directory contains Docker configuration for running the Django server on port 9000.

## Quick Start

### 1. Build and Run Django Server

```bash
cd /media/ego/328010BE80108A8D1/github_public/LivingArchive-Kage-pro
docker-compose -f docker/docker-compose.yml up --build django-server
```

### 2. Access the Server

- **Web Interface**: http://localhost:9000/reconnaissance/
- **API Endpoints**: http://localhost:9000/reconnaissance/api/

### 3. With Database Connection (Optional)

If you want to connect to PostgreSQL databases, create a `.env` file in the `docker/` directory:

```bash
cp docker/.env.example docker/.env
# Edit docker/.env with your database credentials
```

Then run:

```bash
docker-compose -f docker/docker-compose.yml up --build django-server
```

## Configuration

### Environment Variables

The Django server supports the following environment variables:

- `SECRET_KEY` - Django secret key (default: auto-generated insecure key)
- `DEBUG` - Debug mode (default: True)
- `PORT` - Server port (default: 9000)
- `DB_HOST` - PostgreSQL host (REQUIRED, default: localhost)
- `DB_USER` - PostgreSQL user (default: postgres)
- `DB_PASSWORD` - PostgreSQL password (default: postgres)
- `CUSTOMER_EGGS_DB_NAME` - Customer eggs database name (default: customer_eggs)
- `CUSTOMER_EGGS_DB_PORT` - Customer eggs database port (default: 15440)
- `EGG_DB_NAME` - Egg records database name (default: ego) - used as default database
- `EGG_DB_PORT` - Egg records database port (default: 5436)

**Note:** PostgreSQL is required. SQLite has been removed to avoid corruption issues.

### Volumes

- `staticfiles/` - Static files directory (CSS, JS, images)
- `config/` - Configuration files (read-only)

## Docker Compose Services

### Django Server Only

```bash
docker-compose -f docker/docker-compose.yml up django-server
```

### Django Server + Daemons

```bash
docker-compose -f docker/docker-compose.yml up
```

This will start:
- Django server on port 9000
- Kage daemon (port scanner)
- Kumo daemon (HTTP spider)
- Ryu daemon (threat assessment)

## Development

### Rebuild After Code Changes

```bash
docker-compose -f docker/docker-compose.yml up --build django-server
```

### View Logs

```bash
docker-compose -f docker/docker-compose.yml logs -f django-server
```

### Run Django Management Commands

```bash
docker-compose -f docker/docker-compose.yml exec django-server python manage.py migrate
docker-compose -f docker/docker-compose.yml exec django-server python manage.py collectstatic
```

### Access Django Shell

```bash
docker-compose -f docker/docker-compose.yml exec django-server python manage.py shell
```

## Production Considerations

For production deployment:

1. **Set a strong SECRET_KEY**:
   ```bash
   export SECRET_KEY=$(python -c 'from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())')
   ```

2. **Set DEBUG=False**:
   ```bash
   export DEBUG=False
   ```

3. **Use a production WSGI server** (update Dockerfile.django CMD):
   ```dockerfile
   CMD ["gunicorn", "ryu_project.wsgi:application", "--bind", "0.0.0.0:9000", "--workers", "4"]
   ```

4. **Add gunicorn to requirements.txt**:
   ```
   gunicorn>=21.2.0
   ```

5. **Configure proper ALLOWED_HOSTS** in `settings.py`

## Troubleshooting

### Port 9000 Already in Use

If port 9000 is already in use, change the port mapping in `docker-compose.yml`:

```yaml
ports:
  - "9001:9000"  # Use 9001 on host, 9000 in container
```

### Database Connection Issues

**PostgreSQL is required** - SQLite is not supported.

1. Check that PostgreSQL server is running:
   ```bash
   # If using Docker for PostgreSQL
   docker ps | grep postgres
   
   # Or check if PostgreSQL is running on host
   sudo systemctl status postgresql
   ```

2. Verify database credentials in `docker/.env` file:
   - `DB_HOST` - Must be set (default: localhost)
   - `DB_USER` - PostgreSQL username
   - `DB_PASSWORD` - PostgreSQL password
   - `EGG_DB_NAME` - Database name (default: ego)
   - `EGG_DB_PORT` - Database port (default: 5436)

3. Test connection from container:
   ```bash
   docker compose -f docker/docker-compose.yml exec django-server python manage.py dbshell
   ```

4. If connecting to host PostgreSQL from Docker container:
   - Use `host.docker.internal` as `DB_HOST` (Docker Desktop)
   - Or use host network mode
   - Or use host's IP address

### Static Files Not Loading

Run collectstatic:
```bash
docker-compose -f docker/docker-compose.yml exec django-server python manage.py collectstatic --noinput
```

## Health Check

The container includes a health check that verifies the Django server is responding:

```bash
docker ps  # Check health status
docker inspect recon-django | grep -A 10 Health
```

