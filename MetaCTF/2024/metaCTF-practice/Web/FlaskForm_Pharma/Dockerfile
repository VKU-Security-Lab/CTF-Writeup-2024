FROM python:3.11-slim

RUN apt update && apt upgrade -y && apt install procps -y
RUN python3 -m pip install flask werkzeug

WORKDIR /app

COPY server.py /app/server.py
COPY app.py /app/app.py
COPY flag.txt /app/flag.txt
COPY readflag /app/readflag
COPY potion_details /app/potion_details
COPY templates /app/templates
COPY static /app/static

RUN chmod 555 /app/readflag
RUN chmod 400 /app/flag.txt
RUN chown root:root /app/flag.txt
RUN chmod u+s /app/readflag

RUN groupadd -g 1337 werkzeug && \
    useradd -r -u 1337 -g werkzeug werkzeug

USER werkzeug

ENTRYPOINT [ "python3" ]
CMD [ "/app/server.py" ]