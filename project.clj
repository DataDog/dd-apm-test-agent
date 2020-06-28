(defproject test-agent "0.1.0-SNAPSHOT"
  :description "Integration test agent for Datadog tracing libraries"
  :url "https://github.com/kyle-verhoog/dd-trace-test-agent"
  :min-lein-version "2.0.0"
  :dependencies [[org.clojure/clojure "1.10.1"]
                 [clojure-msgpack "1.2.1"]
                 [com.taoensso/timbre "4.10.0"]
                 [compojure "1.6.1"]
                 [ring/ring-defaults "0.3.2"]]
  :plugins [[lein-ring "0.12.5"] [lein-cljfmt "0.6.7"]]
  :ring {:handler test-agent.handler/app
         :port 8126}
  :profiles
  {:dev {:dependencies [[javax.servlet/servlet-api "2.5"]
                        [ring/ring-mock "0.3.2"]]}})
