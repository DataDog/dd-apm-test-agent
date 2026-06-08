FROM python:3.13-slim

WORKDIR /src
EXPOSE 8126

# The agent binds to loopback by default. In a container the published port
# (EXPOSE 8126 / -p 8126:8126) is only reachable if the agent binds all
# interfaces, so opt in explicitly here.
ENV HOST=0.0.0.0
ENV SNAPSHOT_CI=1
ENV LOG_LEVEL=INFO
ENV SNAPSHOT_DIR=/snapshots
ENV VCR_CASSETTES_DIRECTORY=/vcr-cassettes

RUN apt update && \
    apt install -y --no-install-recommends git curl runc containerd && \
    rm -rf /var/lib/apt/lists/*

ADD vcr-cassettes /vcr-cassettes

# Add only necessary files to speed up development builds
ADD README.md setup.py test_deps.txt ./
ADD ddapm_test_agent ./ddapm_test_agent
ADD .git ./.git
RUN pip install /src && \
    rm -rf /root/.cache/pip

CMD ["ddapm-test-agent"]
