(ns test-agent.handler-test
  (:require [clojure.test :refer :all]
            [ring.mock.request :as mock]
            [test-agent.handler :refer :all]))

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
