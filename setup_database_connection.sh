#!/bin/bash
# Setup script to connect LivingArchive-Kage-pro to the same databases as port 9000 server
# Source: /mnt/webapps-nvme/EgoQT/src/django_bridge/settings.py

# Database Configuration
# Connected to the same databases as the port 9000 Django server

export DB_HOST=localhost
export DB_USER=postgres
export DB_PASSWORD=postgres

# Customer Eggs Database (EggRecord, Nmap, RequestMetadata tables)
# Port 15440 - ego-customer-eggs-db container
export CUSTOMER_EGGS_DB_NAME=customer_eggs
export CUSTOMER_EGGS_DB_PORT=15440

# EggRecords Database (learning, heuristics, WAF detections)
# Port 5436 - egoqt-postgres container
# Database name: 'ego' (not 'ego_main')
export EGG_DB_NAME=ego
export EGG_DB_PORT=5436

echo "✅ Database environment variables configured!"
echo ""
echo "Database connections:"
echo "  - customer_eggs: ${DB_HOST}:${CUSTOMER_EGGS_DB_PORT}/${CUSTOMER_EGGS_DB_NAME}"
echo "  - eggrecords: ${DB_HOST}:${EGG_DB_PORT}/${EGG_DB_NAME}"
echo ""
echo "To use these settings, run:"
echo "  source setup_database_connection.sh"
echo "  python manage.py runserver"
echo ""
echo "Or add these exports to your shell profile for persistence."

