(ns dbug-agent.handler
  (:require [clojure.set :as set]
            [compojure.core :refer :all]
            [compojure.route :as route]
            [msgpack.core :as msg]
            [ring.middleware.defaults :refer [wrap-defaults api-defaults]]
            [ring.middleware.reload :refer [wrap-reload]])
  (:use [clojure.pprint]
        [clojure.data])
  )

(defn map-reduce
  ([f acc l] (map-reduce f acc l []))
  ([f acc l lp]
   (if (empty? l) lp
       (let [[acc x] (f acc (first l))]
         (map-reduce f acc (rest l) (conj lp x))))))

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
     (defn trace-check [trace]
       (let [trace-ids (set (map #(% "trace_id") trace))
             span-ids (map #(% "span_id") trace)]

         ;; ensure no collisions in span ids
         (when (not= (count span-ids) (count (set span-ids)))
           (throw (ex-info "Collision in span ids for trace trace" {})))

         ;; ensure only one root span
         (def roots (filter (fn [s] (nil? (s "parent_id"))) trace))
         (when (not= (count roots) 1)
           (throw (ex-info "Multiple root spans in trace" {})))

         ;; check for mismatching trace ids in a trace
         (when (> (count trace-ids) 1)
           (throw (ex-info (format "Multiple trace ids in trace %s" trace-ids) {})))))

     ;; collect traces together since traces can be fragmented
     (def traces (parse-spans (reduce concat raw-traces)))
     (doall (map trace-check raw-traces))

     ;; TODO: check that all referenced spans exist (maybe distributed tracing issues?)
     traces)))

(defn check-traces [token]
  (let [raw-traces (or (@trace-db token) (throw (ex-info (format "Token '%s' not found" token) {})))
        parsed-traces (parse-traces raw-traces)]
    raw-traces))

(defn spans->childmap [spans]
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
(defn trace->str [trace] (with-out-str (pprint (:spans trace))))
(defn span->str [span] (with-out-str (pprint span)))
(defn trace-id [trace] ((trace-root trace) "trace_id"))
(defn next-row [cmap cs]
  (reduce concat (map (fn [s] (cmap (s "span_id"))) cs)))
(defn trace-flatten-bfs
  [trace]
  (let [cmap (:childmap trace)
        root (trace-root trace)
        flattened
        ((fn flat [spans res]
           (if (empty? spans) res
             (flat (next-row cmap spans)
                   (concat res spans))))
               [root] [])
        ]
    flattened))
; (defn trace-fold
;   ([f initacc trace]
;    (let
;      [cmap (:childmap trace)
;       res ((fn fold [f acc span] ) initacc)
;       ]
;      res
;      )))

(defn span-similarity [s1 s2]
  (- 0
     (if (= (s1 "name") (s2 "name")) 0 1)
     (if (= (s1 "service") (s2 "service")) 0 1)
     (if (= (s1 "type") (s2 "type")) 0 1)
     (if (= (s1 "error") (s2 "error")) 0 1)
     (if (= (s1 "resource") (s2 "resource")) 0 1)))

(defn trace-similarity [t1 t2]
  ; Calculate a similarity score between two traces used to match traces
  (- 0
     ;; penalize the difference in the number of traces
     (Math/abs (- (trace-count t1) (trace-count t2)))

     ;; compare root spans
     (* -1 (span-similarity (trace-root t1) (trace-root t2)))))

(defn match-traces [t1s t2s]
  ; Attempts to match traces based on their similarity
  (let [t2-match
        (fn [avail-t2s t1]
          (let
           [match (reduce
                   (fn [{score :score cur-t2 :t2 avail-t2s :avail-t2s :as st} t2]
                     (let [new-score (trace-similarity t1 t2)]
                       (cond (not (contains? avail-t2s (trace-id t2))) (assoc st :t1 t1)
                             (or (nil? score) (> new-score score))
                             {:score new-score
                              :t1 t1
                              :t2 t2
                              :avail-t2s
                              (disj
                               (if (nil? cur-t2) avail-t2s (conj avail-t2s (trace-id cur-t2)))
                               (trace-id t2))}
                             (< new-score score) (assoc st :t1 t1)
                             :else (throw (ex-info "TODO" {}))))) {:avail-t2s avail-t2s} t2s)]
            [(:avail-t2s match) match]))
        matches (map-reduce t2-match (set (map trace-id t2s)) t1s)]

    ; Check for any unmatched traces
    (do
      (def unmatched-t1-ids
        (set (map #(-> % :t1 trace-id) (filter #(not (contains? % :t2)) matches))))
      (when (not (empty? unmatched-t1-ids))
        (def traces (filter #(contains? unmatched-t1-ids (trace-id %)) t1s))
        (def fmt-traces (clojure.string/join "\n" (map trace->str traces)))
        (throw (ex-info (format "Unmatched actual traces:\n%s" fmt-traces) {})))

      (def t2-ids (set (map trace-id t2s)))
      (def matched-t2-ids (set (map #(-> % :t2 trace-id) matches)))
      (def unmatched-t2-ids (set/difference t2-ids matched-t2-ids))
      (when (not (empty? unmatched-t2-ids))
        (def traces (filter #(contains? unmatched-t2-ids (trace-id %)) t2s))
        (def fmt-traces (clojure.string/join "\n" (map trace->str traces)))
        (throw (ex-info (format "Did not receive expected traces:\n%s" fmt-traces) {})))
      matches)))

(defn render-shape
  ([childmap] (render-shape childmap (childmap nil)))
  ([childmap spans]
   (if (empty? spans)
     ""
     (str (count spans) "\n"
          (render-shape childmap (next-row childmap spans))))
  ))

;; TODO: better visualization
(defn diff-shape
  ([act exp]
   (diff-shape (:childmap act) [(trace-root act)]
               (:childmap exp) [(trace-root exp)]))
  ([actmap actspans expmap expspans]
   (cond
     (= (count actspans) (count expspans))
     (cond
       (= (count actspans) 0) nil
       :else (diff-shape actmap (next-row actmap actspans)
                         expmap (next-row expmap expspans)))
     :else
     (throw (ex-info (format "Trace shape difference.\nExpected shape:\n%s\nGot shape:\n%s" (render-shape expmap) (render-shape actmap)) {})))))

(defn span-ignore [span ignores]
  (let
    [span (apply dissoc span ignores)
     span (update span "meta" #(apply dissoc % ignores))
     span (update span "metrics" #(apply dissoc % ignores))
     ]
    span))

(defn diff-span [ignores act exp]
  (do
    (def act-ig (span-ignore act ignores))
    (def exp-ig (span-ignore exp ignores))
    ; Check that attributes are all present and their values match
    (defn merge-keys [span]
      (let
        [merged (merge
                  span
                  (reduce-kv (fn [m k v] (assoc m (format "meta.%s" k) v)) {} (span "meta"))
                  (reduce-kv (fn [m k v] (assoc m (format "metrics.%s" k) v)) {} (span "metrics")))]
        (apply dissoc merged ["metrics" "meta"])))

    (def act-merge (merge-keys act))
    (def exp-merge (merge-keys exp))
    (def all-keys (set (concat (keys act-merge) (keys exp-merge))))
    (def requires ["name"
                   "service"
                   "span_id"
                   "trace_id"
                   "duration"
                   "start"
                   "error"
                   ])

    (def results
      (for [k (set (concat (keys act-merge) (keys exp-merge) requires))
            :let [in-act (contains? act-merge k)
                  in-exp (contains? exp-merge k)
                  act-val (act-merge k)
                  exp-val (exp-merge k)
                  ignored (contains? ignores k)
                  required (contains? requires k)
                  [result reason]
                  (cond
                    (and in-act (not in-exp))
                    [:failed (format "Key '%s' not expected." k)]
                    (and (not in-act) in-exp)
                    [:failed (format "Key '%s' in expected not actual." k)]
                    (and (not ignored) (not= act-val exp-val))
                    [:failed (format "Value mismatch for '%s'. Expected: '%s' got '%s' " k exp-val act-val)]
                    :else [:passed ""])
                  ]]
        {:key k
          :ignored ignored
          :required required
          :in-act in-act
          :act-val act-val
          :in-exp in-exp
          :exp-val exp-val
          :result result
          :reason reason}))

    (def errors (filter #(= (:result %) :failed) results))
    (def human-errors (clojure.string/join "\n" (map #(str "❌ " (:reason %)) errors)))

    (when (not (empty? errors))
      (throw (ex-info (format "Span data mismatch.\n%s\n\nActual:\n%s\nExpected:\n%s" human-errors (span->str act) (span->str exp)) {}))
      )))

(defn diff-spans [act exp]
  (let [act-bfs (trace-flatten-bfs act)
        exp-bfs (trace-flatten-bfs exp)
        diff-span (partial diff-span (set ["span_id"
                                      "trace_id"
                                      "parent_id"
                                      "duration"
                                      "start"
                                      "metrics.system.pid"
                                      "meta.runtime-id"]))
        ]
    (doall (map diff-span act-bfs exp-bfs))))

(defn diff-traces [act exp]
  (do
    ; check the shape of the trace
    (diff-shape act exp)

    ; actually diff the spans now
    (diff-spans act exp)
    ))

(defn diff-matches [matches]
  (map (fn [match] (diff-traces (:t1 match) (:t2 match))) matches))

;; TODO: add ignore tags
(defn compare-traces [act-traces ref-traces]
  (let [act-traces (map spans->trace act-traces)
        ref-traces (map spans->trace ref-traces)
        matched-traces (match-traces act-traces ref-traces)
        diffed-traces (diff-matches matched-traces)]
    (pprint diffed-traces)))

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
       [traces (check-traces token)]
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
       [act-traces (check-traces token)]
        (if (snapexists token)
          ;; snapshot exists, do the comparison
          (let
           [ref-traces (read-string (slurp (snappath token)))]
            (compare-traces act-traces ref-traces)
            (println (format "[%s] tests passed!" token))
            {:status 200 :headers {"Content-Type" "text/plain"} :body (str token)})
          ;; snapshot does not exist so write the traces
          (do
            (spit (snappath token) (with-out-str (pprint act-traces)))
            {:status 200 :headers {"Content-Type" "text/plain"} :body "OK :)"})))
      (catch clojure.lang.ExceptionInfo e
        (let [msg (str (.getMessage e) "\nSee '" (snappath token) "' for the expected traces.")]
        {:status 500 :headers {"Content-Type" "text/plain"} :body msg}))
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
