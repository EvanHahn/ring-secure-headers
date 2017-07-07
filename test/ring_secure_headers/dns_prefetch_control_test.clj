(ns ring-secure-headers.dns-prefetch-control-test
  (:require [clojure.test :refer :all]
            [ring-secure-headers.test-helpers :refer [dummy-handler make-test-helper]]
            [ring-secure-headers.core :refer [dns-prefetch-control]]))

(def test-helper (make-test-helper dns-prefetch-control "x-dns-prefetch-control"))

(deftest dns-prefetch-control-happy-path-test
  (testing "sets header to 'off' when passed no options"
    (test-helper {:expected "off"}))
  (testing "sets header to 'off' when passed empty options"
    (test-helper {:options {} :expected "off"}))
  (testing "sets header to 'off' when asked to"
    (test-helper {:options {:allow? false} :expected "off"}))
  (testing "sets header to 'on' when asked to"
    (test-helper {:options {:allow? true} :expected "on"})))

(deftest dns-prefetch-control-sad-path-test
  (testing "throws when not passed a map"
    (is (thrown? Exception (dns-prefetch-control dummy-handler 123)))
    (is (thrown? Exception (dns-prefetch-control dummy-handler [:max-age 123])))))
