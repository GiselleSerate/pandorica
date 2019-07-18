FROM ubuntu:bionic

LABEL description="Pandorica"
LABEL version="0.1"
LABEL maintainer="sp-solutions@paloaltonetworks.com"

WORKDIR /app
ADD requirements.txt /app/requirements.txt

SHELL ["/bin/bash", "-c"]
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get -y install --no-upgrade software-properties-common build-essential python-dev python-setuptools python3-pip python3.7-venv wget unzip netcat docker docker.io

# Set up Python virtual env
RUN ["python3.7", "-m", "venv", "/root/.env"]
RUN ["/root/.env/bin/pip", "install", "--upgrade", "pip"]
RUN ["/root/.env/bin/pip", "install", "-r", "requirements.txt"]

# Get driver
# RUN ["wget", "https://chromedriver.storage.googleapis.com/2.41/chromedriver_linux64.zip"]
# RUN ["unzip", "chromedriver_linux64.zip"]
# RUN ["mv", "chromedriver", "/usr/bin/chromedriver"]


COPY src /app/src

EXPOSE 80 5900

# RUN ["/root/.env/bin/python", "/app/src/parser.py"]
