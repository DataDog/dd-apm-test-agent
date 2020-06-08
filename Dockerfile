FROM clojure

RUN mkdir -p /usr/src/agent
WORKDIR /usr/src/agent
COPY project.clj /usr/src/agent/
RUN lein deps
COPY . /usr/src/agent
RUN mv "$(lein ring uberjar | sed -n 's/^Created \(.*standalone\.jar\)/\1/p')" app-standalone.jar
CMD ["java", "-jar", "app-standalone.jar"]
