(ns ring-secure-headers.expect-ct-test
  (:require [clojure.test :refer :all]
            [ring-secure-headers.core :refer [expect-ct]]))

(defn- expecter [expected]
  (fn [request]
    (is (= expected (request "expect-ct")))))

(deftest expect-ct-test
  (testing "sets max-age to 0 when given no options"
    (let [raw-handler (fn [request]
                    (is (= "max-age=0" (get-in request [:headers "expect-ct"]))))
          augmented-handler (expect-ct raw-handler)]
      (augmented-handler {}))))
