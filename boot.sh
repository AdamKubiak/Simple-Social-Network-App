#!/bin/sh
source venv/bin/activate
while true; do
    flask deploy
    if [ $? -eq 0 ]; then
        break
    fi
    echo "Deploy command didn't work, trying again in 5 seconds"
    sleep 5
done
exec gunicorn -b :5000 --access-logfile - --error-logfile - flasky:app
