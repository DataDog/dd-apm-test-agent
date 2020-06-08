# dbug-agent

## Prerequisites

You will need [Leiningen][] 2.0.0 or above installed.

[leiningen]: https://github.com/technomancy/leiningen

## Running

To start a web server for the application, run:

    lein ring server 8126

    lein ring server-headless 8126


## Packaging

To package as a jar:

    lein ring uberjar  # java -jar target/...jar
    # run the jar
    PORT=8126 java -jar target/dbug-agent-....jar

## Formatting

To format the code:

    lein cljfmt check
    lein cljfmt fix
