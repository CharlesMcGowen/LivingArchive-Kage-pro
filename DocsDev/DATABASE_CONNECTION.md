# Database Connection Setup

This document explains how to connect LivingArchive-Kage-pro to the same databases used by the Django server running on port 9000.

## Database Configuration

The port 9000 server uses these database connections (from `/mnt/webapps-nvme/EgoQT/src/django_bridge/settings.py`):

### Customer Eggs Database
- **Host**: localhost
- **Port**: 15440 (ego-customer-eggs-db container)
- **Database**: customer_eggs
- **User**: postgres
- **Password**: postgres
- **Tables**: EggRecord, Nmap, RequestMetadata

### EggRecords Database
- **Host**: localhost
- **Port**: 5436 (egoqt-postgres container)
- **Database**: ego (NOT 'ego_main')
- **User**: postgres
- **Password**: postgres
- **Tables**: Learning data, heuristics, WAF detections, technology fingerprints

## Setup Methods

### Method 1: Use Setup Script (Recommended)

```bash
cd /media/ego/328010BE80108A8D1/github_public/LivingArchive-Kage-pro
source setup_database_connection.sh
python manage.py runserver
```

### Method 2: Export Environment Variables Manually

```bash
export DB_HOST=localhost
export DB_USER=postgres
export DB_PASSWORD=postgres
export CUSTOMER_EGGS_DB_NAME=customer_eggs
export CUSTOMER_EGGS_DB_PORT=15440
export EGG_DB_NAME=ego
export EGG_DB_PORT=5436

python manage.py runserver
```

### Method 3: Create .env File

Create a `.env` file in the project root:

```env
DB_HOST=localhost
DB_USER=postgres
DB_PASSWORD=postgres
CUSTOMER_EGGS_DB_NAME=customer_eggs
CUSTOMER_EGGS_DB_PORT=15440
EGG_DB_NAME=ego
EGG_DB_PORT=5436
```

The `settings.py` file already loads `.env` files using `python-dotenv` if available.

## Verification

Test the database connections:

```bash
python manage.py shell
```

Then in the Python shell:

```python
from django.db import connections

# Test customer_eggs connection
conn = connections['customer_eggs']
cursor = conn.cursor()
cursor.execute("SELECT 1")
print("✅ customer_eggs connected!")

# Test eggrecords connection  
conn2 = connections['eggrecords']
cursor2 = conn2.cursor()
cursor2.execute("SELECT 1")
print("✅ eggrecords connected!")

# Test querying data
from ryu_app.postgres_models import PostgresEggRecord
count = PostgresEggRecord.objects.using('customer_eggs').count()
print(f"✅ Found {count} EggRecords in customer_eggs database")
```

## Important Notes

1. **Database Router**: The `PostgresRouter` in `ryu_app/db_router.py` automatically routes PostgreSQL models to the correct database.

2. **Shared Data**: Once connected, both projects will access the same data:
   - Edits in LivingArchive-Kage-pro will be visible in the port 9000 server
   - Edits in the port 9000 server will be visible in LivingArchive-Kage-pro

3. **Connection Pooling**: Both databases use `CONN_MAX_AGE=0` to prevent connection pool exhaustion.

4. **Application Names**: Each connection uses a unique `application_name` for monitoring:
   - `livingarchive_customer_eggs`
   - `livingarchive_eggrecords`

## Troubleshooting

### Connection Refused
- Check that Docker containers are running:
  ```bash
  docker ps | grep -E "customer-eggs|egoqt-postgres"
  ```

### Authentication Failed
- Verify database credentials match the Docker container configuration
- Check if password is different from default 'postgres'

### Database Not Found
- Verify database names: `customer_eggs` and `ego` (not `ego_main`)
- Check that databases exist in the containers

### Port Already in Use
- The ports 15440 and 5436 are mapped from Docker containers
- If ports conflict, check Docker port mappings

