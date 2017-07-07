(ns ring-secure-headers.expect-ct-test
  (:require [clojure.test :refer :all]
            [ring-secure-headers.test-helpers :refer [dummy-handler make-test-helper]]
            [ring-secure-headers.core :refer [expect-ct]]))

(def test-helper (make-test-helper expect-ct "expect-ct"))

(deftest expect-ct-happy-path-test
  (testing "sets max-age to 0 when given no options"
    (test-helper {:expected "max-age=0"}))
  (testing "sets max-age to 0 when given an empty map"
    (test-helper {:options {} :expected "max-age=0"}))
  (testing "sets max-age when provided as an integer"
    (test-helper {:options {:max-age 0} :expected "max-age=0"})
    (test-helper {:options {:max-age 123} :expected "max-age=123"}))
  (testing "enforcement"
    (test-helper {:options {:enforce? true} :expected "enforce; max-age=0"}))
  (testing "explicitly disabling enforcement"
    (test-helper {:options {:enforce? false} :expected "max-age=0"}))
  (testing "sets report-uri"
    (test-helper {:options {:report-uri "https://example.com/report"}
                  :expected "max-age=0; report-uri=\"https://example.com/report\""}))
  (testing "sets enforcement, max-age, and report-uri all together"
    (test-helper {:options {:max-age 123
                            :enforce? true
                            :report-uri "https://example.com/r"}
                  :expected "enforce; max-age=123; report-uri=\"https://example.com/r\""})))

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
