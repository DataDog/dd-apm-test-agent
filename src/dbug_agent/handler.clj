(ns dbug-agent.handler
  (:require [compojure.core :refer :all]
            [compojure.route :as route]
            [msgpack.core :as msg]
            [ring.middleware.defaults :refer [wrap-defaults api-defaults]]
            [ring.middleware.reload :refer [wrap-reload]]))

(defn trace-db-validator [db] true)

(def trace-db
  ; map[token, list[trace]]
  ; stores the raw traces for a test token
  (atom {} :validator (fn [db] true)))

(add-watch trace-db
           :logger
           (fn [key watched old-state new-state]
             (println new-state)))

(defn db-add-traces
  [token traces]
  (swap! trace-db update-in [token] concat traces)
  traces)

(defn parse-spans
  ; parses spans into traces
  ([spans] (parse-spans spans {}))
  ([spans traces]
   (if (empty? spans)
     traces
     (let
      [span (first spans)]
       (parse-spans (rest spans) (assoc-in traces [(span "trace_id") (span "span_id")] span))))))

(defn parse-traces
  ([raw-traces]
   (do
     ;; check for empty traces
     (when (not-empty (filter empty? raw-traces))
       (throw (ex-info (format "Empty traces from client") {})))

     ;; checks done on each raw trace that was received
     (defn raw-trace-check [raw-trace]
       (let [trace-ids (set (map #(% "trace_id") raw-trace))
             span-ids (map #(% "span_id") raw-trace)]

         ;; ensure no collisions in span ids
         (when (not= (count span-ids) (count (set span-ids)))
           (throw (ex-info (format "Collision in span ids for trace trace") {})))

         ;; check for mismatching trace ids in a trace
         (when (> (count trace-ids) 1)
           (throw (ex-info (format "Multiple trace ids in trace %s" trace-ids) {})))))
     (doall (map raw-trace-check raw-traces))

     ;; collect traces together since traces can be fragmented
     (def traces (parse-spans (reduce concat raw-traces)))

     ;; check that all referenced spans exist (TODO distributed tracing issues?)
     traces)))

(defn trace-check [token]
  (let [raw-traces (or (@trace-db token) (throw (ex-info (format "Token '%s' not found" token) {})))
        parsed-traces (parse-traces raw-traces)]
    raw-traces))

(defn mw-encoding [handler]
  (fn [req]
    (let [encoding (get-in req [:headers "content-type"])
          raw-body (get req :body)
          body (cond
                 (= encoding "application/msgpack") (msg/unpack raw-body)
                 (= encoding "application/json") nil  ; TODO support json
                 :else nil)]

      (handler (assoc req :body body)))))

(defn handle-traces [req]
  (let [token (get-in req [:headers "x-datadog-test-token"] "none")
        traces (get req :body)]
    (db-add-traces token traces)
    {:status 200 :headers {"Content-Type" "application/json"} :body "\"OK\""}))

(defn handle-check [req]
  (let [token (get-in req [:headers "x-datadog-test-token"] "none")]
    (try
      (let
       [traces (trace-check token)]
        {:status 200 :headers {"Content-Type" "application/json"} :body traces})
      (catch clojure.lang.ExceptionInfo e
        {:status 500 :headers {"Content-Type" "application/json"} :body (.getMessage e)}))))

(defroutes app-routes
  (mw-encoding (PUT "/v0.4/traces" [] handle-traces))
  (GET "/test/check" [] handle-check)
  (route/not-found "Not Found"))

(def app
  (wrap-defaults app-routes api-defaults))

(def reloadable-app
  (wrap-reload #'app))
