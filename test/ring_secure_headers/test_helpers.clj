(ns ring-secure-headers.test-helpers
  (:require [clojure.test :refer [is]]))

(def dummy-handler (constantly {}))

(defn make-test-helper [middleware default-header-key]
  (fn [options]
    (let [expected (:expected options)
          header-key (get options :header-key default-header-key)
          request (get options :request {})

          options? (contains? options :options)
          wrapped-handler (if options?
                            (middleware dummy-handler (:options options))
                            (middleware dummy-handler))

          response (wrapped-handler request)
          actual (get-in response [:headers header-key])]
      (is (= expected actual)))))
