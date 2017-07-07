(ns ring-secure-headers.hpkp-test
  (:require [clojure.test :refer :all]
            [ring-secure-headers.test-helpers :refer [dummy-handler make-test-helper]]
            [ring-secure-headers.core :refer [hpkp]]))

(def test-helper (make-test-helper hpkp "public-key-pins"))

(deftest hpkp-happy-path-test
  (testing "sets header with SHAs and max-age"
    (test-helper {:options {:max-age 10
                            :sha256s ["abc123" "xyz456"]}
                  :expected "pin-sha256=\"abc123\"; pin-sha256=\"xyz456\"; max-age=10"}))
  (testing "subdomain inclusion"
    (test-helper {:options {:max-age 10
                            :sha256s ["abc123" "xyz456"]
                            :include-subdomains? true}
                  :expected "pin-sha256=\"abc123\"; pin-sha256=\"xyz456\"; max-age=10; includeSubDomains"}))
  (testing "setting a report-uri"
    (test-helper {:options {:max-age 10
                            :sha256s ["abc123" "xyz456"]
                            :report-uri "https://example.com/report"}
                  :expected "pin-sha256=\"abc123\"; pin-sha256=\"xyz456\"; max-age=10; report-uri=\"https://example.com/report\""}))
  (testing "setting a report-uri and subdomain inclusion"
    (test-helper {:options {:max-age 10
                            :sha256s ["abc123" "xyz456"]
                            :include-subdomains? true
                            :report-uri "https://example.com/report"}
                  :expected "pin-sha256=\"abc123\"; pin-sha256=\"xyz456\"; max-age=10; includeSubDomains; report-uri=\"https://example.com/report\""}))
  (testing "setting Report-Only header"
    (let [base-options {:max-age 10
                        :sha256s ["abc123" "xyz456"]
                        :report-uri "https://example.com/report"
                        :report-only? true}
          expected "pin-sha256=\"abc123\"; pin-sha256=\"xyz456\"; max-age=10; report-uri=\"https://example.com/report\""]
      (test-helper {:options base-options :expected expected :header-key "public-key-pins-report-only"})
      (test-helper {:options base-options :expected nil :header-key "public-key-pins"}))))

(deftest hpkp-sad-path-test
  (testing "throws when not passed a map"
    (is (thrown? Exception (hpkp dummy-handler)))
    (is (thrown? Exception (hpkp dummy-handler nil)))
    (is (thrown? Exception (hpkp dummy-handler "let's get it"))))
  (testing "throws when passed empty options"
    (is (thrown? Exception (hpkp dummy-handler {}))))
  (testing "throws when passed a bogus max-age"
    (let [opts {:sha256s ["abc123" "xyz456"]}]
      (is (thrown? Exception (hpkp dummy-handler opts)))
      (is (thrown? Exception (hpkp dummy-handler (assoc opts :max-age 0))))
      (is (thrown? Exception (hpkp dummy-handler (assoc opts :max-age -1))))
      (is (thrown? Exception (hpkp dummy-handler (assoc opts :max-age 1.2))))
      (is (thrown? Exception (hpkp dummy-handler (assoc opts :max-age "12"))))))
  (testing "throws when passed fewer than two SHA256s"
    (let [opts {:max-age 100}]
      (is (thrown? Exception (hpkp dummy-handler opts)))
      (is (thrown? Exception (hpkp dummy-handler (assoc opts :sha256s nil))))
      (is (thrown? Exception (hpkp dummy-handler (assoc opts :sha256s []))))
      (is (thrown? Exception (hpkp dummy-handler (assoc opts :sha256s ["abc123"]))))))
  (testing "throws when passed a non-string report-uri"
    (let [opts {:max-age 100 :sha256s ["abc123" "xyz456"]}]
      (is (thrown? Exception (hpkp dummy-handler (assoc opts :report-uri nil))))
      (is (thrown? Exception (hpkp dummy-handler (assoc opts :report-uri 123))))))
  (testing "throws when using Report-Only header without a report-uri"
    (is (thrown? Exception (hpkp dummy-handler {:max-age 123
                                                :sha256s ["abc123" "xyz456"]
                                                :report-only? true})))))
