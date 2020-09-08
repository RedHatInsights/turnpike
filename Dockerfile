FROM python:3.6-slim-buster

WORKDIR /usr/src/app

ENV FLASK_RUN_HOST 0.0.0.0
ENV BACKENDS_CONFIG_MAP=/etc/turnpike/backends.yml
COPY ./Pipfile ./Pipfile.lock /usr/src/app/
RUN pip install --no-cache-dir --upgrade pip pipenv && apt-get update && \
    apt-get install -y pkg-config gcc libxmlsec1 libxmlsec1-dev --no-install-suggests --no-install-recommends && \
    pipenv lock --requirements > requirements.txt && \
    pip install --no-cache-dir -r requirements.txt && \
    apt-get remove --purge --auto-remove -y gcc pkg-config && \
    rm -rf /var/lib/apt/lists/*
COPY . /usr/src/app/
CMD ["./run-server.sh"]
