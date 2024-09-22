mysqld --init-file=/app/db/init.sql --user=root --bind=0.0.0.0 &
sleep 10
python3 app.py
