FROM python:3.12.2-slim

RUN apt-get update && apt-get -y install socat

WORKDIR /app

ADD jail.py /app/jail.py
ADD flag.txt /flag.txt
RUN chown root:root /app
RUN chmod 555 /app
RUN chown root:root /app/jail.py
RUN chown root:root /flag.txt

RUN useradd app -M -U
USER app

ENV PYTHON_UNBUFFERED=1

CMD socat -s -d -d TCP4-LISTEN:4000,fork,reuseaddr EXEC:"python3 /app/jail.py"

