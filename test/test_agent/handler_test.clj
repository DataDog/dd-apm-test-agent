(ns test-agent.handler-test
  (:require [clojure.test :refer :all]
            [ring.mock.request :as mock]
            [test-agent.handler :refer :all]))

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
