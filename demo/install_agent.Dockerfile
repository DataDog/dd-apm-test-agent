FROM ghcr.io/pawelchcki/apm-cli-poc/java/realworld-backend-micronaut/realworld-backend-micronaut:v1 AS app
ADD https://github.com/DataDog/dd-trace-java/releases/download/v1.37.0/dd-java-agent.jar /dd-java-agent.jar

# install ddapm-test-agent
COPY --from=ghcr.io/pawelchcki/ddapm-test-agent:latest / /

CMD [ "/bin/run_with_agent", "java", "-javaagent:/dd-java-agent.jar", "-jar", "./realworld-backend-micronaut.jar" ]