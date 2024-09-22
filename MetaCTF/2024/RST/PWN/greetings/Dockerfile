# To run: 
# 1. docker build . -t greetings
# 2. docker run -p1337:5000 --privileged greetings
FROM pwn.red/jail

COPY --from=ubuntu@sha256:dda6886d8d153a2d86f046c9335123c6151d83fd63e446b752ed8d9da261205d / /srv
COPY flag.txt /srv/app/flag.txt
COPY greetings /srv/app/run

