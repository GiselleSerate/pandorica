# Only for testing. Don't use for actual deployment.
FROM python:3.6.8-alpine3.8

LABEL description="Pandorica"
LABEL version="0.1"
LABEL maintainer="sp-solutions@paloaltonetworks.com"

WORKDIR /app

# Get curl for mappings
RUN apk add curl

# Move mappings install directory
COPY install /app/install

# Set up Python virtual env
RUN ["python", "-m", "venv", "/root/.env"]
RUN ["/root/.env/bin/pip", "install", "--upgrade", "pip"]

# Copy + install requirements
COPY requirements.txt /app/requirements.txt
RUN ["/root/.env/bin/pip", "install", "-r", "requirements.txt"]

# Copy + install src dir as editable
COPY src /app/src
RUN ["/root/.env/bin/pip", "install", "-e", "src"]

# Put .panrc in ~
COPY .panrc /root/.panrc

EXPOSE 80 5900

# Go directly to Python
CMD ["/root/.env/bin/python", "src/test/test_parser.py"]
