# Only for testing. Don't use for actual deployment, because some of these things rely on things in the test environment. I'm not going to type out an essay in this line about how I know this is bad. Roll with it for now.
# FROM ubuntu:bionic
FROM python:3.6.8-alpine3.8

LABEL description="Pandorica"
LABEL version="0.1"
LABEL maintainer="sp-solutions@paloaltonetworks.com"

# # Docker client
# USER root
# RUN curl -fsSLO https://get.docker.com/builds/Linux/x86_64/docker-17.04.0-ce.tgz \
#   && tar xzvf docker-17.04.0-ce.tgz \
#   && mv docker/docker /usr/local/bin \
#   && rm -r docker docker-17.04.0-ce.tgz

WORKDIR /app
COPY src /app/src
COPY .panrc /root/.panrc

ADD requirements.txt /app/requirements.txt

# SHELL ["/bin/bash", "-c"]

# Set up Python virtual env
RUN ["python", "-m", "venv", "/root/.env"]
RUN ["/root/.env/bin/pip", "install", "--upgrade", "pip"]
RUN ["/root/.env/bin/pip", "install", "-r", "requirements.txt"]
RUN ["/root/.env/bin/pip", "install", "-e", "src"]

EXPOSE 80 5900

# RUN ["/root/.env/bin/python", "-m", "pytest", "-v"]
# WORKDIR /app/src/test
CMD ["/root/.env/bin/python", "src/test/test_parser.py"]
