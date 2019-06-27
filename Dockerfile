FROM dorowu/ubuntu-desktop-lxde-vnc:bionic

LABEL description="Pandorica"
LABEL version="0.1"
LABEL maintainer="sp-solutions@paloaltonetworks.com"

WORKDIR /app
ADD requirements.txt /app/requirements.txt

SHELL ["/bin/bash", "-c"]
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get -y install --no-upgrade software-properties-common build-essential python-dev python-setuptools python3-pip python3.6-venv
RUN ["python3.6", "-m", "venv", "/root/.env"]

RUN ["/root/.env/bin/pip", "install", "--upgrade", "pip"]
RUN ["/root/.env/bin/pip", "install", "-r", "requirements.txt"]

COPY src /app/src


EXPOSE 80 5900
RUN ["/root/.env/bin/python", "/app/src/parser.py"]
