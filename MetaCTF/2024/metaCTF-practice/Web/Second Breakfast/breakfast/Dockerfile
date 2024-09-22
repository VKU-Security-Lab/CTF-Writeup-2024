FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN apt-get update
RUN apt-get install -y mariadb-server

RUN mkdir /run/mysqld/

COPY . .

CMD ["bash", "start.sh"]
