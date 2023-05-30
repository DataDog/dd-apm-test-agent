#!/bin/bash

docker buildx build --platform linux/amd64,linux/arm64/v8 -t williamconti549/dd-apm-test-agent:documentation --push .