FROM python:3.9

EXPOSE 8126

ENV SNAPSHOT_CI=1
ENV LOG_LEVEL=INFO
ENV SNAPSHOT_DIR=/snapshots

RUN mkdir -p /src
WORKDIR /
COPY . /
RUN pip install . --use-feature=in-tree-build .
CMD ["ddapm-test-agent"]
