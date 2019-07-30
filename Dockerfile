# Only for testing. Don't use for actual deployment.
FROM python:3.6.8-alpine3.8

LABEL description="Pandorica"
LABEL version="0.1"
LABEL maintainer="sp-solutions@paloaltonetworks.com"

WORKDIR /app
COPY src /app/src
COPY .panrc /root/.panrc

ADD requirements.txt /app/requirements.txt

# Set up Python virtual env
RUN ["python", "-m", "venv", "/root/.env"]
RUN ["/root/.env/bin/pip", "install", "--upgrade", "pip"]
RUN ["/root/.env/bin/pip", "install", "-r", "requirements.txt"]
RUN ["/root/.env/bin/pip", "install", "-e", "src"]

EXPOSE 80 5900

CMD ["/root/.env/bin/python", "src/test/test_parser.py"]
