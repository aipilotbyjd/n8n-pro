#!/bin/sh
# entrypoint.sh

# Wait for the database to be ready
echo "Waiting for postgres..."
while ! nc -z $DB_HOST $DB_PORT; do
  sleep 0.1
done
echo "PostgreSQL started"

# Run database migrations
echo "Running database migrations..."
/app/bin/admin migrate up
if [ $? -ne 0 ]; then
    echo "Migrations failed"
    exit 1
fi
echo "Migrations completed"

# Execute the main command
exec "$@"
