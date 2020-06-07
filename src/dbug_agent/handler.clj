(ns dbug-agent.handler
  (:require [compojure.core :refer :all]
            [compojure.route :as route]
            [msgpack.core :as msg]
            [ring.middleware.defaults :refer [wrap-defaults api-defaults]]
            [ring.middleware.reload :refer [wrap-reload]]
            ))


(defn trace-db-validator
  [db]
  true
  )

(def trace-db
  ; map[token, list[trace]]
  ; stores the raw traces for a test token
  (atom {}
        :validator (fn [db] true)
        ))

(add-watch trace-db
           :logger
           (fn [key watched old-state new-state]
             (println "old")
             (println old-state)
             (println "new")
             (println new-state)
             ))

(defn db-add-traces
  [token traces]
  (swap! trace-db update-in [token] concat traces)
  traces)


(defn trace-check [token]
  (get-in @trace-db [token])
  )



(defn mw-encoding [handler]
  (fn [req]
    (let [
          encoding (get-in req [:headers "content-type"])
          raw-body (get req :body)
          body (cond
            (= encoding "application/msgpack") (msg/unpack raw-body)
            (= encoding "application/json") nil  ; TODO support json
            :else nil
            )
          ]
      (handler (assoc req :body body))
      )))


(defn handle-traces [req]
  (let [
        ntraces (get-in req [:headers "x-datadog-trace-count"])
        token (get-in req [:headers "x-datadog-test-token"] "none")
        traces (get req :body)
        ]
    (db-add-traces token traces)
    {:status 200 :headers {"Content-Type" "application/json"} :body "\"OK\""}
    ))


(defn handle-check [req]
  (let [
        token (get-in req [:headers "x-datadog-test-token"] "none")
        ]
    (try
      (let
        [traces (trace-check token)]
        {:status 200 :headers {"Content-Type" "application/json"} :body "\"OK\""}
        )
      (catch clojure.lang.ExceptionInfo e
          {:status 500 :headers {"Content-Type" "application/json"} :body "\"NOT OK\""}
        )
      )
    )
  )

(defroutes app-routes
  (mw-encoding (PUT "/v0.4/traces" [] handle-traces))
  (GET "/test/check" [] handle-check)
  (route/not-found "Not Found"))

(def app
  (wrap-defaults app-routes api-defaults))

(def reloadable-app
  (wrap-reload #'app))
