(ns ring-secure-headers.core
  (:require [clojure.string :refer [join]]))

(defn- assert-options-map [v]
  (when-not (map? v)
    (throw (ex-info "options must be a map" {:options v}))))

(defn dns-prefetch-control
  ([handler] (dns-prefetch-control handler {}))
  ([handler options]
   (assert-options-map options)
   (let [result (if (:allow? options) "on" "off")]
     (fn [request]
       (handler (assoc-in request [:headers "x-dns-prefetch-control"] result))))))

(defn expect-ct
  ([handler] (expect-ct handler {}))
  ([handler options]
   (assert-options-map options)

   (let [with-enforce (if (:enforce? options) ["enforce"] [])

         raw-max-age (get options :max-age 0)
         max-age (if (and (integer? raw-max-age) (>= raw-max-age 0))
                   raw-max-age
                   (throw (ex-info "max-age must be 0 or greater" {:max-age raw-max-age})))
         with-max-age (conj with-enforce (str "max-age=" max-age))

         report-uri (:report-uri options)
         with-report-uri (cond
                           (string? report-uri)
                           (conj with-max-age (str "report-uri=\"" report-uri "\""))
                           (contains? options :report-uri)
                           (throw (ex-info "report-uri must be a string" {:report-uri report-uri}))
                           :default
                           with-max-age)

         result (join "; " with-report-uri)]

     (fn [request]
       (handler (assoc-in request [:headers "expect-ct"] result))))))
