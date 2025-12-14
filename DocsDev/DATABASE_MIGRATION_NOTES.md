# Database Migration Notes - LivingArchive-Kage-pro

## Databases Migrated from egoqt/src

### 1. Nmap Agents Database (Reconnaissance)
**Source:** `egoqt/src/django_bridge/settings.py`

**Databases:**
- **customer_eggs** (Port 15440)
  - Contains: EggRecord tables, Nmap scan results, RequestMetadata
  - Already configured in Kage-pro ✅
  
- **eggrecords** (Port 5436) 
  - Contains: Learning database, heuristics, WAF detections
  - Already configured as default database ✅

**Status:** ✅ Already configured - no changes needed

### 2. Oak Knowledge Database
**Source:** `egoqt/src/django_bridge/settings.py` + `artificial_intelligence/personalities/coordination/oak/db_router.py`

**Database:**
- **oak_knowledge** (Port 5436)
  - Contains: Oak task queue, coordination data, knowledge system
  - Router: `OakKnowledgeRouter` routes all Oak models to this database

**Configuration Added:**
- ✅ Added `oak_knowledge` database to `settings.py`
- ✅ Added environment variables to `docker/env.example`
- ✅ Added environment variables to `docker/docker-compose.yml`
- ⚠️ Oak app not yet installed (commented out in INSTALLED_APPS)

## Database Configuration Summary

### Current Databases in Kage-pro:

1. **default** (eggrecords/ego on port 5436)
   - Primary Django database
   - Used for Django models, sessions, etc.

2. **customer_eggs** (port 15440)
   - Nmap scan results
   - EggRecord tables
   - RequestMetadata

3. **eggrecords** (port 5436)
   - Learning database
   - Heuristics
   - WAF detections

4. **oak_knowledge** (port 5436) - NEW
   - Oak task queue
   - Coordination data
   - Knowledge system

## To Enable Oak Support

1. **Install Oak app** (if available):
   ```python
   INSTALLED_APPS = [
       # ... existing apps ...
       'artificial_intelligence.personalities.coordination.oak',
   ]
   ```

2. **Add Oak router**:
   ```python
   DATABASE_ROUTERS = [
       'ryu_app.db_router.PostgresRouter',
       'artificial_intelligence.personalities.coordination.oak.db_router.OakKnowledgeRouter',
   ]
   ```

3. **Run migrations**:
   ```bash
   docker compose -f docker/docker-compose.yml exec django-server python manage.py migrate --database=oak_knowledge
   ```

## Environment Variables

Add to `docker/.env`:
```bash
# Oak Knowledge Database
OAK_DB_NAME=oak_knowledge
OAK_DB_PORT=5436
```

## Notes

- All databases use the same PostgreSQL host (`DB_HOST`)
- Oak and eggrecords share the same port (5436) but are different databases
- Nmap agents use `customer_eggs` database (port 15440)
- Database routers ensure models are routed to correct databases

## Migration Status

✅ **Nmap Agents**: Already configured (customer_eggs + eggrecords)
✅ **Oak Database**: Configuration added, ready for app installation
⚠️ **Oak App**: Not yet installed (needs to be added if Oak functionality is needed)

