FROM clojure

EXPOSE 8126

RUN mkdir -p /src
WORKDIR /src
COPY project.clj /src/
RUN lein deps
COPY . /src
RUN lein uberjar
CMD ["java", "-jar", "target/test-agent.jar"]
