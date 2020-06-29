(ns test-agent.handler-test
  (:require [clojure.test :refer :all]
            [ring.mock.request :as mock]
            [test-agent.handler :refer :all])
  (:use [clojure.pprint]))


; reference implementation
(defn traces->snapshot-ref [traces]
  ; Generates a snapshot from a list of traces
  (with-out-str (pprint (doall (map :spans traces)))))


(defn trace->snapshot
  ([trace] (trace->snapshot trace ""))
  ([trace s] (pprint (trace-flatten-dfs trace))))


(defn traces->snapshot
  ; Generates a snapshot from a list of traces
  ; Since the snapshot is to be human verifiable and checked into version
  ; control it must be made as readable as possible.
  ; To achieve this the following steps are taken:
  ;  - Traces are stored as list of spans which is the popular way in which
  ;    traces are represented in tracing libraries.
  ;  - Common and required attributes are listed first in a consistent order.
  ;  - All custom attributes are sorted alphanumerically afterward.
  ;  - Trace ids are mapped to their position.
  ;  - Span ids are reassigned to their BFS order.
  ;    eg:  [       0       ]
  ;         [   1   ] [  2  ]
  ;         [3][4][5] [6] [7]
  ;  - Spans are placed in DFS order as to be indented to indicate parenting.
  ;    eg:  0
  ;           1
  ;             3
  ;             4
  ;             5
  ;           2
  ;             6
  ;  - Annotations can be added to known tags.
  ;      eg: "_dd.measured 1 ; this span is measured"
  ;  - Braces are inlined whenever possible (except across traces) to reduce
  ;    diff sizes.
  ;
  ; The format output is actually meant to be valid Clojure which makes it
  ; trivial to parse. This was done to simplify development while also
  ; piggy-backing on Clojure's attempt to make "code is data is readable" true.
  ; However, it may make sense to decouple parseability and readability if it
  ; becomes too difficult to maintain both in a single format.
  ([traces] (traces->snapshot traces ""))
  ([traces s]
   (let [snapshots (map trace->snapshot traces)])))


(defn rand-str [len]
    (apply str (take len (repeatedly #(char (+ (rand 26) 65))))))

(defn rand-long [n]
  (long (rand n)))


(defn mkspan
  ([] {"name" (rand-str 6)
       "resource" (rand-str 8)
       "span_id" (rand-long 4294967296)
       "trace_id" (rand-long 4294967296)
       "parent_id" (rand-long 4294967296)
       "service" (rand-str 5)
       "type" (rand-str 5)
       "error" (rand-int 1)
       "duration" (rand-int 20000)
       "start" (rand-int 30000)
       "meta" {}
       "metrics" {}
       })
  ([attrs]
   (let [default-attrs (mkspan)]
     (merge default-attrs attrs))))

(defn mkparent
  ([] (mkparent {}))
  ([attrs] (mkspan (merge {"parent_id" nil} attrs))))

(defn mktrace
  ; TODO: parent and shape
  ([n] (let [tid (rand-long 4294967296)]
         (map (fn [x] (mkspan {"trace_id" tid})) (range n)))))


(deftest test-trace->dfs
  (testing "1 span trace"
    (let [raw-trace [(mkparent)]
          trace (spans->trace raw-trace)
          dfs (trace-flatten-dfs trace)]
      (is (= (count dfs) (count raw-trace)))))
  (testing "already in DFS"
    (let [raw-trace [(mkparent {"span_id" 0})
                     (mkspan {"parent_id" 0 "start" 0})
                     (mkspan {"parent_id" 0 "start" 1 "span_id" 1})
                     (mkspan {"parent_id" 1})]
          trace (spans->trace raw-trace)
          dfs (trace-flatten-dfs trace)]
      (is (= dfs raw-trace))))
  (testing "not in DFS"
    (let [raw-trace [(mkparent {"span_id" 0})
                     (mkspan {"parent_id" 0 "start" 1 "span_id" 1})
                     (mkspan {"parent_id" 0 "start" 0})
                     (mkspan {"parent_id" 1})]
          trace (spans->trace raw-trace)
          dfs (trace-flatten-dfs trace)]
      (is (not= dfs raw-trace)))))

; (deftest test-trace->snapshot
;   (testing "1 span trace"
;     (let [raw-traces [[{"resource" "test"
;                   "name" "span"
;                   "duration" 123124
;                   "start" 12312321
;                   "error" 0
;                   "span_id" 3425432234
;                   "trace_id" 2143534543543
;                   "type" "redis"
;                   "meta" {"runtime-id" 123
;                           }
;                   "metrics" {"_dd.agent_psr" 1.0
;                              "system.pid" 123}
;                   }]]
;           traces (map spans->trace raw-traces)
;           snapshot (traces->snapshot traces)]
;       (is (string? snapshot))
;       (is (true? (compare-traces (read-string snapshot)
;                                  raw-traces))))))

(deftest test-assemble-traces
  (testing "2 raw traces from same trace"
    (let [trace [[{"name" "s2" "trace_id" 1}]
                 [{"name" "s2" "trace_id" 1}]]
          assembled (assemble-traces trace)]
      (is (= (count assembled) 1))
      (is (= (count (first assembled)) 2))))
  (testing "2 raw traces from different traces"
    (let [trace [[{"name" "s2" "trace_id" 2}]
                 [{"name" "s2" "trace_id" 1}]]
          assembled (assemble-traces trace)]
      (is (= (count assembled) 2))
      (is (= (count (first assembled)) 1))
      (is (= (count (second assembled)) 1)))))


(deftest test-agent
  (testing "/start no token"
    (let [response (app (mock/request :get "/test/start?"))]
      (is (= (:status response) 400))))

  (testing "/start empty token"
    (let [response (app (mock/request :get "/test/start?token="))]
      (is (= (:status response) 400))))

  (testing "not-found route"
    (let [response (app (mock/request :get "/invalid"))]
      (is (= (:status response) 404)))))
