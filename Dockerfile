# Only for testing. Don't use for actual deployment, because some of these things rely on things in the test environment. I'm not going to type out an essay in this line about how I know this is bad. Roll with it for now.
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

COPY src /app/src

EXPOSE 80 5900

# This is the testing stuff (and it is wrong)
RUN ["while", "!", "nc", "-z", "localhost", "9200;", "do", "sleep", "1;", "done"]
RUN ["pytest", "-v"]

# RUN ["/root/.env/bin/python", "/app/src/parser.py"]
