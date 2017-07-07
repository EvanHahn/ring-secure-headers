# ring-secure-headers

Help secure your Ring apps by setting various HTTP headers. It’s not a silver bullet, but it can help! Inspired by [Helmet](https://helmetjs.github.io/) for Node.js.

## Usage

ring-secure-headers is made up of several Ring middleware. You can learn more about this on the [Ring wiki](https://github.com/ring-clojure/ring/wiki/Concepts#middleware).

### DNS Prefetch Control

This middleware lets you disable browsers’ DNS prefetching by setting the `X-DNS-Prefetch-Control` header. For more info, see the [Helmet documentation](https://helmetjs.github.io/docs/dns-prefetch-control/).

```clojure
(require '[ring-secure-headers.core :refer [dns-prefetch-control]])

; Sets X-DNS-Prefetch-Control: off
(dns-prefetch-control my-handler)
(dns-prefetch-control my-handler {:allow? false})

; Sets X-DNS-Prefetch-Control: on
(dns-prefetch-control my-handler {:allow? true})
```

### Don't Sniff Mimetype

This middleware helps prevent browsers from trying to guess ("sniff") the MIME type, which can have security implications. It does this by setting the `X-Content-Type-Options` header to `nosniff`. See the [Helmet docs](https://helmetjs.github.io/docs/dont-sniff-mimetype/) for further explanation.

```clojure
(require '[ring-secure-headers.core :refer [nosniff]])

; Sets X-Content-Type-Options: nosniff
(nosniff my-handler)
```

### Expect-CT

The `Expect-CT` HTTP header tells browsers to expect Certificate Transparency. For more about Certificate Transparency and this header, see [this blog post](https://scotthelme.co.uk/a-new-security-header-expect-ct/) and the [in-progress spec](https://datatracker.ietf.org/doc/draft-stark-expect-ct).

```clojure
(require '[ring-secure-headers.core :refer [expect-ct]])

; Sets Expect-CT: max-age=123
(expect-ct my-handler {:max-age 123})

; Sets Expect-CT: enforce; max-age=123
(expect-ct my-handler {:max-age 123
                       :enforce? true})

; Sets Expect-CT: enforce; max-age=30; report-uri="https://example.com/report"
(expect-ct my-handler {:max-age 30
                       :enforce? true
                       :report-uri "https://example.com/report"})
```

### Frameguard

Frameguard mitigates clickjacking attacks by setting the `X-Frame-Options` header. See the [Helmet docs](https://helmetjs.github.io/docs/frameguard/) for more.

```clojure
(require '[ring-secure-headers.core :refer [frameguard]])

; Don't allow me to be in ANY frames.
; Sets X-Frame-Options: DENY
(frameguard my-handler {:action :deny})

; Only let me be framed by people of the same origin.
; Sets X-Frame-Options: SAMEORIGIN
(frameguard my-handler {:action :same-origin})
(frameguard my-handler)  ; defaults to :same-origin

; Allow from a specific host.
; Sets X-Frame-Options: ALLOW-FROM https://example.com
(frameguard my-handler {:action :allow-from
                        :domain "https://example.com"})
```

### HPKP

The `Public-Key-Pins` header helps keep your users on secure HTTPS. For more, see the [Helmet docs](https://helmetjs.github.io/docs/hpkp/).

```clojure
(require '[ring-secure-headers.core :refer [hpkp]])

; Sets Public-Key-Pins: pin-sha256="AbCdEf123="; pin-sha256="ZyXwVu456="; max-age: 123
(hpkp my-handler {:max-age 123
                  :sha256s ["AbCdEf123=", "ZyXwVu456="]})

; Sets Public-Key-Pins: pin-sha256=...; includeSubDomains
(hpkp my-handler {:max-age 123
                  :sha256s ["AbCdEf123=", "ZyXwVu456="]
                  :include-subdomains? true})

; Sets Public-Key-Pins: pin-sha256=...; report-uri="https://example.com/report"
(hpkp my-handler {:max-age nintey-days-in-seconds
                  :sha256s ["AbCdEf123=", "ZyXwVu456="]
                  :report-uri "https://example.com/report"})

; Sets Public-Key-Pins-Report-Only: pin-sha256=...; report-uri="https://example.com/report"
(hpkp my-handler {:max-age nintey-days-in-seconds
                  :sha256s ["AbCdEf123=", "ZyXwVu456="]
                  :report-uri "https://example.com/report"
                  :report-only? true})
```

### IE No Open

This middleware sets the `X-Download-Options` to prevent Internet Explorer from executing downloads in your site’s context. See [the Helmet docs](https://helmetjs.github.io/docs/ienoopen/) for more.

```clojure
(require '[ring-secure-headers.core :refer [ie-no-open]])

; Sets X-Download-Options: noopen
(ie-no-open my-handler)
```

### XSS Filter

The `xss-filter` middleware sets the `X-XSS-Protection` header to prevent reflected XSS attacks. See [the Helmet docs](https://helmetjs.github.io/docs/xss-filter/) for a more detailed description.

```clojure
(require '[ring-secure-headers.core :refer [xss-filter]])

; Sets X-XSS-Protection: 1; mode=block
(xss-filter my-handler)

; Force the header to be set on old versions of Internet Explorer, which can have other security risks
(xss-filter my-handler {:force-on-old-ie? true})
```

## License

Copyright © 2017 Evan Hahn

Distributed under the Unlicense either version 1.0 and later.
