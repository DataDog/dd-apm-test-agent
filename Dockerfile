FROM python:3.9

EXPOSE 8126

ENV SNAPSHOT_CI=1
ENV LOG_LEVEL=INFO
ENV SNAPSHOT_DIR=/snapshots

WORKDIR /
COPY . /
RUN pip install .
CMD ["ddapm-test-agent"]
