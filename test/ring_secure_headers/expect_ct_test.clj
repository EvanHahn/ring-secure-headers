(ns ring-secure-headers.expect-ct-test
  (:require [clojure.test :refer :all]
            [ring-secure-headers.core :refer [expect-ct]]))

(defn- dummy-handler [_])

(defn- expect-handler [expected]
  (fn [request]
    (let [actual (get-in request [:headers "expect-ct"])]
      (is (= expected actual)))))

(defn- test-helper [options expected]
  (let [handler (expect-ct (expect-handler expected) options)]
    (handler {})))

(deftest expect-ct-happy-path-test
  (testing "sets max-age to 0 when given no options"
    (let [handler (expect-ct (expect-handler "max-age=0"))]
      (handler {})))
  (testing "sets max-age to 0 when given an empty map"
    (test-helper {} "max-age=0"))
  (testing "sets max-age when provided as an integer"
    (test-helper {:max-age 0} "max-age=0")
    (test-helper {:max-age 123} "max-age=123"))
  (testing "enforcement"
    (test-helper {:enforce? true} "enforce; max-age=0"))
  (testing "explicitly disabling enforcement"
    (test-helper {:enforce? false} "max-age=0"))
  (testing "sets report-uri"
    (test-helper {:report-uri "https://example.com/report"}
                 "max-age=0; report-uri=\"https://example.com/report\""))
  (testing "sets enforcement, max-age, and report-uri all together"
    (test-helper {:max-age 123
                  :enforce? true
                  :report-uri "https://example.com/r"}
                 "enforce; max-age=123; report-uri=\"https://example.com/r\"")))

(deftest expect-ct-sad-path-test
  (testing "throws when not passed a map"
    (is (thrown? Exception (expect-ct dummy-handler 123)))
    (is (thrown? Exception (expect-ct dummy-handler [:max-age 123]))))
  (testing "throws when passed a non-integer max-age"
    (is (thrown? Exception (expect-ct dummy-handler {:max-age nil})))
    (is (thrown? Exception (expect-ct dummy-handler {:max-age 123.456})))
    (is (thrown? Exception (expect-ct dummy-handler {:max-age "123"}))))
  (testing "throws when passed a negative max-age"
    (is (thrown? Exception (expect-ct dummy-handler {:max-age -0.1})))
    (is (thrown? Exception (expect-ct dummy-handler {:max-age -1})))
    (is (thrown? Exception (expect-ct dummy-handler {:max-age -1.5})))
    (is (thrown? Exception (expect-ct dummy-handler {:max-age -123}))))
  (testing "throws when passed a non-string report-uri"
    (is (thrown? Exception (expect-ct dummy-handler {:report-uri nil})))
    (is (thrown? Exception (expect-ct dummy-handler {:report-uri 123})))))
