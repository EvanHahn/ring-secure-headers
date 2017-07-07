(ns ring-secure-headers.core
  (:require [clojure.string :refer [join]]))

(defn- wrap [f]
  (fn
    ([handler] (f handler {}))
    ([handler options]
     (when-not (map? options)
       (throw (ex-info "options must be a map" {:options options})))
     (f handler options))))

(def dns-prefetch-control
  (wrap (fn dns-prefetch-control [handler options]
          (let [result (if (:allow? options) "on" "off")]
            (fn [request]
              (handler (assoc-in request [:headers "x-dns-prefetch-control"] result)))))))

(def expect-ct
  (wrap (fn expect-ct [handler options]
          (let [with-enforce (if (:enforce? options) ["enforce"] [])

                raw-max-age (get options :max-age 0)
                max-age (if (and (integer? raw-max-age) (>= raw-max-age 0))
                          raw-max-age
                          (throw (ex-info "max-age must be 0 or greater" {:max-age raw-max-age}))) with-max-age (conj with-enforce (str "max-age=" max-age))

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
              (handler (assoc-in request [:headers "expect-ct"] result)))))))

(def frameguard
  (wrap (fn frameguard [handler options]
          (let [action (get options :action :same-origin)
                domain (:domain options)
                result (case action
                         :deny "DENY"
                         :same-origin "SAMEORIGIN"
                         :allow-from (if (and (string? domain) (not (empty? domain)))
                                       (str "ALLOW-FROM " domain)
                                       (throw (ex-info "ALLOW-FROM requires a non-empty domain string" {:domain domain})))
                         (throw (ex-info "Action must be :deny, :same-origin, or :allow-from" {:action action})))]
            (fn [request]
              (handler (assoc-in request [:headers "x-frame-options"] result)))))))
