(ns ring-secure-headers.nosniff-test
  (:require [clojure.test :refer :all]
            [ring-secure-headers.test-helpers :refer [make-test-helper]]
            [ring-secure-headers.core :refer [nosniff]]))

(def test-helper (make-test-helper nosniff "x-content-type-options"))

(deftest nosniff-happy-path-test
  (testing "sets header to 'nosniff'"
    (test-helper {:expected "nosniff"})))
