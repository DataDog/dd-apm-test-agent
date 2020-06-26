(ns test-agent.handler
  (:require [clojure.set :as set]
            [compojure.core :refer :all]
            [compojure.route :as route]
            [msgpack.core :as msg]
            [ring.middleware.defaults :refer [wrap-defaults api-defaults]]
            [ring.middleware.reload :refer [wrap-reload]])
  (:use [clojure.pprint]
        [clojure.data]))

(defn map-reduce
  ([f acc l] (map-reduce f acc l []))
  ([f acc l lp]
   (if (empty? l) lp
       (let [[acc x] (f acc (first l))]
         (map-reduce f acc (rest l) (conj lp x))))))

(defn long-str [& strings] (clojure.string/join "" strings))


(def snapdir (or (System/getenv "SNAPSHOT_DIR") "snaps"))

(defn errf
  ([msg] (str "\033[91m" msg "\033[0m"))
  ([f msg] (if f (errf msg) msg)))

(defn snappath
  ([snap] (format "%s/%s.snap" snapdir snap))
  ([dir snap] (format "%s/%s.snap" dir snap)))
(defn file-exists? [file] (.exists (clojure.java.io/as-file file)))


; There are only 2 global atoms
; - trace-db: for holding the traces for a token
; - sync-token used to maintain the current synchronous test token

(def trace-db
  ; map[token, list[trace]]
  ; stores the raw traces for a test token
  (atom {} :validator (fn [db] true)))

(defn db-add-traces
  [token traces]
  (swap! trace-db update-in [token] concat traces)
  traces)

(defn db-rm-traces
  [token]
  (println (format "[%s] clearing traces" token))
  (swap! trace-db dissoc token))


(def sync-token
  ; token to be used when running tests synchronously
  (atom nil))

(defn set-sync-token [token] (swap! sync-token (fn [cur-token] token)))
(defn clear-sync-token [] (set-sync-token nil))


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
     (defn trace-check-invariants [trace]
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
     (doall (map trace-check-invariants raw-traces))

     ;; TODO: check that all referenced spans exist (maybe distributed tracing issues?)
     traces)))

(defn check-traces [token]
  (let [raw-traces (or (@trace-db token) (throw (ex-info (format "No traces found for token '%s'." token) {})))
        parsed-traces (parse-traces raw-traces)]
    raw-traces))

(defn spans->childmap [spans]
  ; converts a list of spans into a map of span id to a sorted set
  ; of the span's children (ordered by their start)
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
(defn trace-id [trace] ((trace-root trace) "trace_id"))

(defn next-row [cmap cs]
  (reduce concat (map (fn [s] (cmap (s "span_id"))) cs)))

(defn trace->str
  ([trace] (trace->str trace {}))
  ([trace highlights]
   (let [root (trace-root trace)
         cmap (:childmap trace)
         strace
         ((fn dfs [span d prefix leader cprefix]
            (let [cs (cmap (span "span_id"))
                  nd (inc d)
                  ncp1 (str cprefix "│ ")
                  ncp2 (str cprefix "  ")
                  cp (str prefix cprefix)
                  nc (count cs)
                  ss (cond
                       (= nc 1) [(dfs (first cs) nd cp "└─" "  ")]
                       (= nc 2) [(dfs (first cs) nd cp "├─" "│ ")
                                 (dfs (last cs) nd cp "└─" "  ")]
                       (> nc 2) (concat (map #(dfs % nd cp "├─" "│ ") (->> cs drop-last))
                                      [(dfs (last cs) nd cp "└─" "  ")])
                       :else [])
                  restline (clojure.string/join "" ss)
                  ishighlight (contains? highlights (span "span_id"))
                  hl (if ishighlight
                       (str "<------- " (:msg (highlights (span "span_id"))))
                       "")
                  spanline (errf ishighlight (format "%s%s[%s] %s" prefix leader (span "name") hl))]
              (str spanline "\n" restline)))
          root 0 "" "" "")]
     strace)))

(defn traces->str
  ([traces] (traces->str traces {}))
  ([traces highlights]
   (let
     [joined-str
      (reduce
        (fn [acc t]
          (let [tid (trace-id t)
                ishighlight (contains? highlights tid)
                strace (trace->str t)]
            (str acc "\n" "trace id: " tid "\n" (errf ishighlight strace))))
        "-------------------------------------" traces)]
     (str joined-str "-------------------------------------"))))

(defn trace-flatten-bfs
  [trace]
  (let [cmap (:childmap trace)
        root (trace-root trace)
        flattened
        ((fn flat [spans res]
           (if (empty? spans) res
               (flat (next-row cmap spans)
                     (concat res spans))))
         [root] [])]
    flattened))

(defn span->str [span] (with-out-str (pprint span)))
; meta and metrics can not exist on a span if they are empty
; funny how we optimize that but not error or resource...
(defn span-meta [span] (get span "meta" {}))
(defn span-metrics [span] (get span "metrics" {}))

(defn span-similarity [s1 s2]
  (- 0
     (if (= (s1 "name") (s2 "name")) 0 1)
     (if (= (s1 "service") (s2 "service")) 0 1)
     (if (= (s1 "type") (s2 "type")) 0 1)
     (if (= (s1 "error") (s2 "error")) 0 1)
     (if (= (s1 "resource") (s2 "resource")) 0 1)
     (reduce (fn [acc k] (+ acc (if (= ((span-meta s1) k) ((span-meta s2) k)) 0 1)))
             0 (set (concat (keys (span-meta s1)) (keys (span-meta s2)))))
     (reduce (fn [acc k] (+ acc (if (= ((span-metrics s1) k) ((span-metrics s2) k)) 0 1)))
             0 (set (concat (keys (span-metrics s1)) (keys (span-metrics s2)))))))

(defn trace-similarity [t1 t2]
  ; Calculate a similarity score between two traces used to match traces.
  ; The lower the score the less similar the traces are.
  (- 0
     ; penalize the difference in the number of traces
     (Math/abs (- (trace-count t1) (trace-count t2)))

     (* -1 (reduce (fn [score [s1 s2]] (+ score (span-similarity s1 s2))) 0
                   (map vector (trace-flatten-bfs t1) (trace-flatten-bfs t2))))

     ; compare root spans
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
                             (or (nil? score) (>= new-score score))
                             {:score new-score :t1 t1 :t2 t2
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
        (def fmt-traces (traces->str traces))
        (throw (ex-info (format "Unmatched actual traces:\n%s" fmt-traces) {})))

      (def t2-ids (set (map trace-id t2s)))
      (def matched-t2-ids (set (map #(-> % :t2 trace-id) matches)))
      (def unmatched-t2-ids (set/difference t2-ids matched-t2-ids))
      (when (not (empty? unmatched-t2-ids))
        (def traces (filter #(contains? unmatched-t2-ids (trace-id %)) t2s))
        (def fmt-traces (traces->str traces))
        (throw (ex-info (format "Did not receive expected traces:\n%s" fmt-traces) {})))
      matches)))

(defn render-shape
  ([childmap] (render-shape childmap (childmap nil)))
  ([childmap spans]
   (if (empty? spans)
     ""
     (str (count spans) "\n"
          (render-shape childmap (next-row childmap spans))))))

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
     (throw (ex-info (format "Trace shape difference.") {})))))

(defn span-ignore [span ignores]
  (let
   [span (apply dissoc span ignores)
    span (update span "meta" #(apply dissoc % ignores))
    span (update span "metrics" #(apply dissoc % ignores))]
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
                (reduce-kv (fn [m k v] (assoc m (format "meta.%s" k) v)) {} (span-meta span))
                (reduce-kv (fn [m k v] (assoc m (format "metrics.%s" k) v)) {} (span-metrics span)))]
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
                   "error"])

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
                    [:failed (format "Value mismatch for '%s'. Expected '%s' got '%s' " k exp-val act-val)]
                    :else [:passed ""])]]
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
      (throw (ex-info
              (format "At expected span:\n%s\nReceived actual span:\n%s\nSpan data mismatch.\n%s"
                      (span->str exp) (span->str act) human-errors)
              {:act-span-id (act "span_id")
               :exp-span-id (exp "span_id")
               :msg "Span data mismatch"})))))

(defn diff-spans [act exp ignores]
  (let [act-bfs (trace-flatten-bfs act)
        exp-bfs (trace-flatten-bfs exp)
        diff-span
        (partial diff-span
                 (set (concat ignores ["span_id"
                                       "trace_id"
                                       "parent_id"
                                       "duration"
                                       "start"
                                       "metrics.system.pid"
                                       "meta.runtime-id"])))]
    (doall (map diff-span act-bfs exp-bfs))))

(defn diff-traces [act exp ignores]
  (try
    (do
      ; check the shape of the trace
      (diff-shape act exp)
      ; actually diff the spans now
      (diff-spans act exp ignores))
    (catch clojure.lang.ExceptionInfo e
      ; Prepend trace context info
      (let [msg (.getMessage e)
            data (ex-data e)
            act-sid (:act-span-id data)
            exp-sid (:exp-span-id data)]
        (throw (ex-info
                (format "At expected trace:\n%s\nReceived actual trace:\n%s\n%s"
                        (trace->str exp) (trace->str act {act-sid {:msg (:msg data)}}) msg)
                {:act-trace-id (trace-id act)
                 :exp-trace-id (trace-id exp)}))))))

(defn diff-matches [matches ignores]
  (map (fn [match] (diff-traces (:t1 match) (:t2 match) ignores)) matches))

(defn compare-traces [act-traces exp-traces ignores]
  (let [act-traces (map spans->trace act-traces)
        exp-traces (map spans->trace exp-traces)]
    (try
      (let [matched-traces (match-traces act-traces exp-traces)
            diffed-traces (diff-matches matched-traces ignores)]
        ; need to doall to finally execute all the side-effects
        (doall diffed-traces))
      (catch clojure.lang.ExceptionInfo e
      ; Prepend trace context info
        (let [msg (.getMessage e)
              data (ex-data e)
              act-tid (:act-trace-id data)
              exp-tid (:exp-trace-id data)
              act-str (traces->str act-traces {act-tid {}})
              exp-str (traces->str exp-traces)]
          (throw (ex-info
                  (format "Expected traces:\n%s\nReceived actual traces:\n%s\n%s" exp-str act-str msg) {})))))))

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
  ; middleware for associating a test token for a request from either the
  ; X-Datadog-Test-Token header or token query param with that precedence.
  (fn [req]
    (handler
      (assoc req :token (get-in req [:headers "x-datadog-test-token"] (get (:params req) :token nil))))))

(defn handle-traces [req]
  (let [token (:token req)
        token (if (nil? token) @sync-token token)
        traces (:body req)]
    (println (format "[%s] received %s traces" token (count traces)))
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
  (let [token (:token req)
        dir (get (:params req) :dir snapdir)
        file (get (:params req) :file (snappath dir token))
        ignores (clojure.string/split (get (:params req) :ignores "") #",")]
    (try
      (let
       [act-traces (check-traces token)]
        (if (file-exists? token)
          ; snapshot exists, do the comparison
          (let
           [exp-traces (read-string (slurp file))]
            (compare-traces act-traces exp-traces ignores)
            (println (format "[%s] tests passed!" token))
            {:status 200 :headers {"Content-Type" "text/plain"} :body (str token)})
          ; snapshot does not exist so write the traces
          (do
            (spit file (with-out-str (pprint act-traces)))
            {:status 200 :headers {"Content-Type" "text/plain"} :body "OK :)"})))
      (catch clojure.lang.ExceptionInfo e
        (let [msg (str (.getMessage e) "\n\nSnapfile: '" (snappath token))]
          {:status 500 :headers {"Content-Type" "text/plain"} :body msg}))
      (catch java.io.FileNotFoundException e
        (let [msg (str (.getMessage e) "\nTest agent error :(")]
          {:status 500 :headers {"Content-Type" "text/plain"} :body msg}))
      (finally
        (do
          ; if this was a sync test, clear the sync token
          (when (= token @sync-token)
              (clear-sync-token))
          (db-rm-traces token))))))


(defn handle-start [req]
  (try
    (let [token (get (:params req) :token nil)
          curtoken @sync-token]
      (cond
        (nil? token)
          (throw
            (ex-info
              (format "Received nil token for test case. Did you provide the token query param?") {}))
        (not (nil? curtoken))
         (println (format "WARNING: previous synchronous test '%s' did not complete!" curtoken))
        :else (set-sync-token token)))
    (catch clojure.lang.ExceptionInfo e
      (let [msg (str (.getMessage e) "\n\nFailed to start test case!\n")]
        ; clear the token for future test invocations
        (clear-sync-token)
        {:status 500 :headers {"Content-Type" "text/plain"} :body msg}))))


(defroutes app-routes
  (mw-token (GET "/test/check" [] handle-check))
  (mw-token (GET "/test/clear" [] handle-clear))
  (mw-token (GET "/test/snapshot" [] handle-snapshot))
  (mw-token (GET "/test/start" [] handle-start))
  (mw-token (mw-encoding (PUT "/v0.4/traces" [] handle-traces)))
  (route/not-found "Not Found"))

(def app
  (wrap-defaults app-routes api-defaults))

(def reloadable-app
  (wrap-reload #'app))
