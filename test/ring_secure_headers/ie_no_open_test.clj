(ns ring-secure-headers.ie-no-open-test
  (:require [clojure.test :refer :all]
            [ring-secure-headers.test-helpers :refer [make-test-helper]]
            [ring-secure-headers.core :refer [ie-no-open]]))

(def test-helper (make-test-helper ie-no-open "x-download-options"))

(deftest ie-no-open-happy-path-test
  (testing "sets header to 'noopen'"
    (test-helper {:expected "noopen"})))
