FROM python:3.12-slim

EXPOSE 8126

ENV SNAPSHOT_CI=1
ENV LOG_LEVEL=INFO
ENV SNAPSHOT_DIR=/snapshots

RUN apt update && apt install -y git curl

RUN mkdir -p /src
WORKDIR /src
COPY . /src
RUN pip install /src

# Cleanup
RUN apt remove -y git
RUN rm -rf /var/lib/apt/lists/* /root/.cache/pip /tmp/* /var/tmp/* /src

CMD ["ddapm-test-agent"]
