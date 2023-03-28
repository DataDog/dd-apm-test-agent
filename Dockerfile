# Build stage for linux/amd64
FROM python:3.9 AS builder-amd64
WORKDIR /src
COPY . /src
RUN pip install --upgrade pip
RUN pip install /src

# Build stage for linux/arm64/v8
FROM --platform=linux/arm64/v8 python:3.9 AS builder-arm64v8
WORKDIR /src
COPY . /src
RUN pip install --upgrade pip
RUN pip install /src

# Final stage
FROM python:3.9
ENV SNAPSHOT_CI=1
ENV LOG_LEVEL=INFO
ENV SNAPSHOT_DIR=/snapshots
COPY --from=builder-amd64 /src /src
COPY --from=builder-arm64v8 /src /src
WORKDIR /src
RUN pip install .
EXPOSE 9126
CMD ["ddapm-test-agent"]
