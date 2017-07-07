(ns ring-secure-headers.core
  (:require [clojure.string :refer [join]]
            [ring-secure-headers.internal-util :refer [wrap constantly-set-header conj-report-uri old-ie?]]))

(def dns-prefetch-control
  (wrap (fn dns-prefetch-control [handler options]
          (let [header-value (if (:allow? options) "on" "off")]
            (constantly-set-header handler "x-dns-prefetch-control" header-value)))))

(def expect-ct
  (wrap (fn expect-ct [handler options]
          (let [with-enforce (if (:enforce? options) ["enforce"] [])
                raw-max-age (get options :max-age 0)
                max-age (if (and (integer? raw-max-age) (>= raw-max-age 0))
                          raw-max-age
                          (throw (ex-info "max-age must be 0 or greater" {:max-age raw-max-age}))) with-max-age (conj with-enforce (str "max-age=" max-age))
                with-report-uri (conj-report-uri with-max-age options)
                header-value (join "; " with-report-uri)]
            (constantly-set-header handler "expect-ct" header-value)))))

(def frameguard
  (wrap (fn frameguard [handler options]
          (let [action (get options :action :same-origin)
                domain (:domain options)
                header-value (case action
                               :deny "DENY"
                               :same-origin "SAMEORIGIN"
                               :allow-from (if (and (string? domain) (not (empty? domain)))
                                             (str "ALLOW-FROM " domain)
                                             (throw (ex-info "ALLOW-FROM requires a non-empty domain string" {:domain domain})))
                               (throw (ex-info "Action must be :deny, :same-origin, or :allow-from" {:action action})))]
            (constantly-set-header handler "x-frame-options" header-value)))))

(defn hpkp [handler options]
  (let [raw-shas (:sha256s options)
        shas (if (and (> (count raw-shas) 1) (every? string? raw-shas))
               raw-shas
               (throw (ex-info "sha256s must be a collection of strings" {:sha256s raw-shas})))

        raw-max-age (:max-age options)
        max-age (if (and (integer? raw-max-age) (> raw-max-age 0))
                  raw-max-age
                  (throw (ex-info "max-age must be a positive integer" {:max-age raw-max-age})))

        with-max-age-and-shas (conj (into [] (map #(str "pin-sha256=\"" % \") shas))
                                    (str "max-age=" max-age))

        with-include-subdomains (if (:include-subdomains? options)
                                  (conj with-max-age-and-shas "includeSubDomains")
                                  with-max-age-and-shas)

        with-report-uri (conj-report-uri with-include-subdomains options)

        report-only? (:report-only? options)
        header-key (if report-only? "public-key-pins-report-only" "public-key-pins")

        header-value (join "; " with-report-uri)]

    (when (and report-only? (not (:report-uri options)))
      (throw (ex-info "report-uri must be defined in report-only mode" {})))

    (constantly-set-header handler header-key header-value)))

(defn nosniff [handler]
  (constantly-set-header handler "x-content-type-options" "nosniff"))

(defn ie-no-open [handler]
  (constantly-set-header handler "x-download-options" "noopen"))

(def xss-filter
  (wrap (fn xss-filter [handler options]
          (if (:force-on-old-ie? options)
            (constantly-set-header handler "x-xss-protection" "1; mode=block")
            (fn [request]
              (let [useragent (get-in request [:headers "user-agent"])
                    header-value (if (old-ie? useragent) "0" "1; mode=block")]
                (assoc-in (handler request) [:headers "x-xss-protection"] header-value)))))))
