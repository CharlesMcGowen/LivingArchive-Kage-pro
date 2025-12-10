# PostgreSQL Migration - LivingArchive-Kage-pro

## ✅ SQLite Removed - PostgreSQL is Now Default

SQLite has been removed as the default database to avoid corruption issues. **PostgreSQL is now required.**

## Changes Made

### 1. Settings.py Updated
- **Before**: SQLite as default database
- **After**: PostgreSQL as default database (uses `eggrecords` database on port 5436)
- **Required**: `DB_HOST` environment variable must be set

### 2. Docker Configuration Updated
- Removed SQLite volume mount from `docker-compose.yml`
- `DB_HOST` is now required (defaults to `localhost`)
- Updated environment variable defaults

### 3. Documentation Updated
- All references to SQLite removed
- PostgreSQL connection is now documented as required
- Updated all README files and setup guides

## Configuration

### Required Environment Variables

```bash
DB_HOST=localhost          # PostgreSQL server host (REQUIRED)
DB_USER=postgres           # PostgreSQL username
DB_PASSWORD=postgres       # PostgreSQL password
EGG_DB_NAME=ego            # Default database name (port 5436)
EGG_DB_PORT=5436           # Default database port
```

### Docker Setup

1. **Create `.env` file**:
   ```bash
   cd /media/ego/328010BE80108A8D1/github_public/LivingArchive-Kage-pro
   cp docker/env.example docker/.env
   # Edit docker/.env with your PostgreSQL credentials
   ```

2. **Start Django server**:
   ```bash
   docker compose -f docker/docker-compose.yml up -d django-server
   ```

### Standalone Setup

1. **Set environment variables**:
   ```bash
   export DB_HOST=localhost
   export DB_USER=postgres
   export DB_PASSWORD=postgres
   export EGG_DB_NAME=ego
   export EGG_DB_PORT=5436
   ```

2. **Run migrations**:
   ```bash
   python manage.py migrate
   ```

## Database Connections

The application connects to two PostgreSQL databases:

1. **Default Database** (`eggrecords` on port 5436)
   - Primary Django database
   - Used for Django models, sessions, etc.

2. **Customer Eggs Database** (`customer_eggs` on port 15440)
   - EggRecord tables (Nmap, RequestMetadata)
   - Accessed via `customer_eggs` database alias

3. **EggRecords Database** (`eggrecords` on port 5436)
   - Learning, heuristics, WAF detections
   - Accessed via `eggrecords` database alias
   - Same as default database

## Benefits of PostgreSQL

✅ **No Corruption Issues**: PostgreSQL is much more reliable than SQLite
✅ **Better Performance**: Handles concurrent connections better
✅ **Production Ready**: Suitable for production deployments
✅ **Advanced Features**: Full SQL support, transactions, etc.
✅ **Scalability**: Can handle larger datasets

## Migration Notes

- **No data migration needed**: This is a fresh setup change
- **Existing SQLite databases**: Not used anymore
- **Database router**: Already configured for PostgreSQL models

## Troubleshooting

### Connection Refused
```bash
# Check PostgreSQL is running
sudo systemctl status postgresql

# Test connection
psql -h localhost -U postgres -d ego -p 5436
```

### Database Does Not Exist
```bash
# Create database if needed
createdb -h localhost -U postgres -p 5436 ego
```

### Docker Container Can't Connect to Host PostgreSQL
- Use `host.docker.internal` as `DB_HOST` (Docker Desktop)
- Or use host network mode in docker-compose.yml
- Or use host's IP address

## Summary

✅ **SQLite**: Removed
✅ **PostgreSQL**: Now default and required
✅ **Configuration**: Updated in all files
✅ **Documentation**: Updated to reflect PostgreSQL requirement

**Status**: Ready to use with PostgreSQL! 🐘

