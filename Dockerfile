FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    git ca-certificates openssh-client \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY gaterunner.py /app/gaterunner.py

ENV OUT_DIR=/out
RUN mkdir -p /out && chmod 777 /out
VOLUME ["/out"]

ENTRYPOINT ["python", "/app/gaterunner.py"]
