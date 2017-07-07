(ns ring-secure-headers.test-helpers
  (:require [clojure.test :refer [is]]))

(defn dummy-handler [_])

(defn- expect-handler [header-key expected]
  (fn [request]
    (let [actual (get-in request [:headers header-key])]
      (is (= expected actual)))))

(defn make-test-helper [middleware header-key]
  (fn [options]
    (let [raw-handler (expect-handler header-key (:expected options))
          options? (contains? options :options)
          wrapped-handler (if options?
                            (middleware raw-handler (options :options))
                            (middleware raw-handler))]
      (wrapped-handler {}))))
