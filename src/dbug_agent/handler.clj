(ns dbug-agent.handler
  (:require [compojure.core :refer :all]
            [compojure.route :as route]
            [msgpack.core :as msg]
            [ring.middleware.defaults :refer [wrap-defaults api-defaults]]
            [ring.middleware.reload :refer [wrap-reload]])
  (:use clojure.pprint))

(def snapdir (or (System/getenv "SNAPSHOT_DIR") "snaps"))

(defn snappath [snap] (format "%s/%s.snap" snapdir snap))
(defn snapexists [snap] (.exists (clojure.java.io/as-file (snappath snap))))

(defn trace-db-validator [db] true)

(def trace-db
  ; map[token, list[trace]]
  ; stores the raw traces for a test token
  (atom {} :validator (fn [db] true)))

; (add-watch trace-db
;            :logger
;            (fn [key watched old-state new-state]
;              (println (keys new-state))))

(defn db-add-traces
  [token traces]
  (println (format "[%s] received %s traces" token (count traces)))
  (swap! trace-db update-in [token] concat traces)
  traces)

(defn db-rm-traces
  [token]
  (println (format "[%s] clearing traces" token))
  (swap! trace-db dissoc token))

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

(defn spans->childmap [spans]
  ; (println "WTF")
  ; (println spans)
  ; (println "ENDWTF")
  (let
   [span< (fn [s1 s2] (< (s1 "start") (s2 "start")))
    addchild (fn [mp span]
               (let [pid (span "parent_id")]
                 (assoc mp pid (conj (get mp pid (sorted-set-by span<)) span))))
    childrenmap (reduce addchild {} spans)]
    childrenmap))

(defn spans->trace [spans] {:spans spans :childmap (spans->childmap spans)})
(defn trace-root [trace] (first (get (:childmap trace) nil)))
(defn trace-count [trace] (count (:spans trace)))
; (defn trace->str [trace] (str (span "name") "\n" (tree->str children)))
(defn trace-id [trace] ((trace-root trace) "trace_id"))

(defn span-similarity [s1 s2]
  (- 0
     ;(do (println s1) 0)
     ;(do (println "") 0)
     ;(do (println s2) 0)
     ; (do (println "S1" s1) 0)
     ; (do (println "S2" s2) 0)
     ; (do (println (s1 "resource") (s2 "resource")) 0)
     (if (= (s1 "name") (s2 "name")) 0 1)
     (if (= (s1 "service") (s2 "service")) 0 1)
     (if (= (s1 "resource") (s2 "resource")) 0 1)))

;; calculate a similarity score between two traces used to match traces


(defn trace-similarity [t1 t2]
  (- 0
     ;; penalize the difference in the number of traces
     (Math/abs (- (trace-count t1) (trace-count t2)))

     ;; compare root spans
     (* -1 (span-similarity (trace-root t1) (trace-root t2)))))

(defn match-traces [t1s t2s]
  (let [scores
        (map
          (fn [t1]
            (reduce
              (fn [st t2]
                (let [new-score (trace-similarity t1 t2)]
                  (cond (> new-score (:score st)) {:score new-score :trace t2}
                        (< new-score (:score st)) st
                        :else (throw (ex-info (format "%s" (:score st)) {}))))) {:score -500000 :trace nil} t2s)) t1s)]
    scores))


;; TODO: add ignore tags


(defn compare-traces [raw-act-traces raw-ref-traces]
  (let [act-traces (map spans->trace raw-act-traces)
        ref-traces (map spans->trace raw-ref-traces)
        matched-traces (match-traces act-traces ref-traces)
        ; score-mapping (fold () )
        ]
    (println matched-traces)))

(defn mw-encoding [handler]
  (fn [req]
    (let [encoding (get-in req [:headers "content-type"])
          raw-body (:body req)
          body (cond
                 (= encoding "application/msgpack") (msg/unpack raw-body)
                 (= encoding "application/json") nil  ; TODO support json?
                 :else nil)]
      (handler (assoc req :body body)))))

(defn mw-token [handler]
  (fn [req]
    (handler (assoc req :token (get-in req [:headers "x-datadog-test-token"] "none")))))

(defn handle-traces [req]
  (let [token (:token req)
        traces (:body req)]
    (db-add-traces token traces)
    {:status 200 :headers {"Content-Type" "application/json"} :body "\"OK\""}))

(defn handle-check [req]
  (let [token (:token req)]
    (try
      (let
       [traces (trace-check token)]
        {:status 200 :headers {"Content-Type" "application/json"} :body traces})
      (catch clojure.lang.ExceptionInfo e
        {:status 500 :headers {"Content-Type" "application/json"} :body (.getMessage e)}))))

(defn handle-clear [req]
  (let [token (:token req)]
    (db-rm-traces token)))

(defn handle-snapshot [req]
  (let [token (:token req)]
    (try
      (let
       [act-traces (trace-check token)]
        (if (snapexists token)
          ;; snapshot exists, do the comparison
          (let
           [ref-traces (read-string (slurp (snappath token)))]
            ; (println (first ref-traces))
            ; (println (first (first ref-traces)))
            ; (println ((first (first ref-traces)) "name"))
            (compare-traces act-traces ref-traces)
            {:status 200 :headers {"Content-Type" "text/plain"} :body (str token)})

          ;; snapshot does not exist so write the traces
          (do
            (spit (snappath token) (with-out-str (pr act-traces)))
            {:status 500 :headers {"Content-Type" "text/plain"} :body "OK :)"})))
      (catch clojure.lang.ExceptionInfo e
        ;; TODO? write log file with a bunch of useful information
        {:status 500 :headers {"Content-Type" "text/plain"} :body (.getMessage e)})
      (finally (db-rm-traces token)))))

(defroutes app-routes
  (mw-token (mw-encoding (PUT "/v0.4/traces" [] handle-traces)))
  (mw-token (GET "/test/check" [] handle-check))
  (mw-token (GET "/test/clear" [] handle-clear))
  (mw-token (GET "/test/snapshot" [] handle-snapshot))
  (route/not-found "Not Found"))

(def app
  (wrap-defaults app-routes api-defaults))

(def reloadable-app
  (wrap-reload #'app))
