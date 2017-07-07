(ns ring-secure-headers.core)

(defn expect-ct
  ([handler] (expect-ct handler {}))

  ([handler options]
    (fn [request]
      (handler (assoc-in request [:headers "expect-ct"] "max-age=0")))))
