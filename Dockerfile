FROM python:3.9

EXPOSE 8126

ENV SNAPSHOT_CI=1
ENV LOG_LEVEL=INFO
ENV SNAPSHOT_DIR=/snapshots

RUN mkdir -p /src
WORKDIR /src
COPY . /src
RUN pip install /src
CMD ["ddapm-test-agent"]
