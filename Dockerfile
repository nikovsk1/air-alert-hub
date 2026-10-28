# Multi-arch base image supporting linux/arm/v7, linux/arm64, linux/amd64
FROM --platform=$TARGETPLATFORM python:3.12-alpine

LABEL maintainer="Air Alert Radar Hub"
LABEL description="Air Threat Radar Hub Microservice for Home Assistant & ESP32-S3 AMOLED"

WORKDIR /app

# Install minimal OS dependencies for timezone and TLS certificates
RUN apk add --no-cache tzdata ca-certificates

# Install python dependencies (Pure-python or prebuilt wheels on ARMv7)
RUN pip install --no-cache-dir aiohttp websockets

COPY app.py /app/app.py
COPY oblast_detector.py /app/oblast_detector.py
COPY regions.geojson /app/regions.geojson
COPY data/ /app/data_defaults/

EXPOSE 8088

ENV PYTHONUNBUFFERED=1
ENV PORT=8088

CMD ["python", "-u", "/app/app.py"]
