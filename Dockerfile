FROM python:3.11

EXPOSE 8126

ENV SNAPSHOT_CI=1
ENV LOG_LEVEL=INFO
ENV SNAPSHOT_DIR=/snapshots
COPY --from=builder-amd64 /src /src
COPY --from=builder-arm64v8 /src /src
WORKDIR /src
RUN pip install .
EXPOSE 9126
CMD ["ddapm-test-agent"]
