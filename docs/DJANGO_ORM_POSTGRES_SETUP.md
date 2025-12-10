# Django ORM PostgreSQL Setup

This document describes the Django ORM setup for PostgreSQL database access in the LivingArchive-Kage project.

## Overview

The project now uses Django ORM models instead of raw SQL for accessing the PostgreSQL `customer_eggs` database. This provides:

- **Type Safety**: IDE autocomplete and type checking
- **Maintainability**: Easier to read and modify code
- **Django Features**: Access to annotations, aggregations, querysets, etc.
- **Consistency**: Same ORM patterns across the codebase

## Architecture

### 1. PostgreSQL Models (`ryu_app/postgres_models.py`)

Models that map to existing PostgreSQL tables:

- `PostgresEggRecord` - Maps to `customer_eggs_eggrecords_general_models_eggrecord`
- `PostgresNmap` - Maps to `customer_eggs_eggrecords_general_models_nmap`
- `PostgresRequestMetadata` - Maps to `customer_eggs_eggrecords_general_models_requestmetadata`
- `PostgresDNSQuery` - Maps to `customer_eggs_eggrecords_general_models_dnsquery`

**Important**: All models have `managed = False` in their Meta class, meaning Django won't create/delete these tables (they already exist in PostgreSQL).

### 2. Database Router (`ryu_app/db_router.py`)

The `PostgresRouter` automatically routes PostgreSQL models to the `customer_eggs` database:

- Read operations → `customer_eggs` database
- Write operations → `customer_eggs` database
- Relations allowed between models in same database
- Migrations disabled for `customer_eggs` (tables are managed externally)

### 3. Settings Configuration (`ryu_project/settings.py`)

The router is registered in settings:

```python
DATABASE_ROUTERS = ['ryu_app.db_router.PostgresRouter']
```

## Usage Examples

### Creating Records

```python
from ryu_app.postgres_models import PostgresEggRecord
from django.utils import timezone
import uuid

# Create a new eggrecord
eggrecord = PostgresEggRecord.objects.using('customer_eggs').create(
    id=uuid.uuid4(),
    subDomain='subdomain.example.com',
    domainname='example.com',
    alive=True,
    eggname='Customer Name',
    projectegg='ALPHA',
    created_at=timezone.now(),
    updated_at=timezone.now()
)
```

### Querying Records

```python
from ryu_app.postgres_models import PostgresEggRecord, PostgresNmap
from django.db.models import Count

# Get all eggrecords with counts
eggrecords = PostgresEggRecord.objects.using('customer_eggs').annotate(
    nmap_count=Count('nmap_scans', distinct=True),
    request_count=Count('http_requests', distinct=True),
    dns_count=Count('dns_queries', distinct=True)
).order_by('-updated_at')[:200]

# Filter records
alive_records = PostgresEggRecord.objects.using('customer_eggs').filter(alive=True)

# Get related records
eggrecord = PostgresEggRecord.objects.using('customer_eggs').get(id=some_id)
nmap_scans = eggrecord.nmap_scans.all()  # Related manager works!
```

### Using the Router (Automatic)

You can also rely on the router to automatically select the database:

```python
# Router will automatically use 'customer_eggs' for PostgresEggRecord
eggrecord = PostgresEggRecord.objects.get(id=some_id)  # No .using() needed!
```

However, it's recommended to explicitly use `.using('customer_eggs')` for clarity.

## Refactored Views

The following views have been refactored to use Django ORM:

1. **`create_eggrecord_api`** - Creates eggrecords using `PostgresEggRecord.objects.create()`
2. **`eggrecord_list`** - Lists eggrecords with annotations for counts

## Database Configuration

The PostgreSQL database is configured in `settings.py` via environment variables:

- `DB_HOST` - PostgreSQL host
- `DB_USER` - Database user
- `DB_PASSWORD` - Database password
- `CUSTOMER_EGGS_DB_NAME` - Database name (default: `customer_eggs`)
- `CUSTOMER_EGGS_DB_PORT` - Database port (default: `15440`)

## Migration Notes

- **PostgreSQL models are `managed = False`**: Django won't create migrations for these models
- **Local SQLite models**: Still use normal Django migrations (`ryu_app/migrations/`)
- **Column additions**: If you need to add columns to PostgreSQL tables, do it manually or via SQL migrations

## Benefits

1. **No more raw SQL**: Clean, maintainable code
2. **Type safety**: IDE support and fewer runtime errors
3. **Django features**: Annotations, aggregations, prefetch_related, etc.
4. **Consistency**: Same patterns as local SQLite models
5. **Relations**: Foreign keys work automatically with related managers

## Future Improvements

Consider refactoring other views that still use raw SQL:

- Dashboard views that query Nmap scans
- Views that aggregate RequestMetadata
- Views that query DNS queries

All of these can now use the Django ORM models for cleaner code.

