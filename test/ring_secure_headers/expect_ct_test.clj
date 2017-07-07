(ns ring-secure-headers.expect-ct-test
  (:require [clojure.test :refer :all]
            [ring-secure-headers.core :refer [expect-ct]]))

(defn- expect-handler [expected]
  (fn [request]
    (let [actual (get-in request [:headers "expect-ct"])]
      (is (= expected actual)))))

(deftest expect-ct-test
  (testing "sets max-age to 0 when given no options"
    (let [handler (expect-ct (expect-handler "max-age=0"))]
      (handler {}))))
