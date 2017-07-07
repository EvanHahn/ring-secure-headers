(ns ring-secure-headers.test-helpers
  (:require [clojure.test :refer [is]]))

(def dummy-handler (constantly {}))

(defn make-test-helper [middleware header-key]
  (fn [options]
    (let [expected (:expected options)
          options? (contains? options :options)
          wrapped-handler (if options?
                            (middleware dummy-handler (options :options))
                            (middleware dummy-handler))
          response (wrapped-handler {})
          actual (get-in response [:headers header-key])]
      (is (= expected actual)))))
