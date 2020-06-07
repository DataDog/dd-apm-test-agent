# dbug-agent

## Prerequisites

You will need [Leiningen][] 2.0.0 or above installed.

[leiningen]: https://github.com/technomancy/leiningen

## Running

To start a web server for the application, run:

    lein ring server

    lein ring server-headless


## Packaging

To package as a jar:

    lein ring uberjar  # java -jar target/...jar
