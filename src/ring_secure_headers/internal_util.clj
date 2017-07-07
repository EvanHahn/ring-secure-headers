(ns ring-secure-headers.internal-util)

(defn wrap [f]
  (fn
    ([handler] (f handler {}))
    ([handler options]
     (when-not (map? options)
       (throw (ex-info "options must be a map" {:options options})))
     (f handler options))))

(defn constantly-set-header [handler header-key header-value]
  (fn [request]
    (assoc-in (handler request) [:headers header-key] header-value)))

(defn conj-report-uri [coll options]
  (let [report-uri (:report-uri options)]
    (cond
      (string? report-uri)
      (conj coll (str "report-uri=\"" report-uri "\""))
      (contains? options :report-uri)
      (throw (ex-info "report-uri must be a string" {:report-uri report-uri}))
      :default
      coll)))
