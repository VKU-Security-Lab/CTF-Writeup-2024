FROM ubuntu@sha256:562456a05a0dbd62a671c1854868862a4687bf979a96d48ae8e766642cd911e8

RUN apt-get update && apt-get install python3.12 python3-pip python3-flask -y

RUN mkdir /app
ADD ./app /app

RUN chown -R root:root /app/
RUN chmod -R 444 /app/
RUN chmod 555 /app/ /app/templates

RUN groupadd -r app && useradd -r -g app app

USER app

CMD [ "python3", "/app/app.py" ]
