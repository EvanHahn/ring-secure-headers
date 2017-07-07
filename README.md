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

## License

Copyright © 2017 Evan Hahn

Distributed under the Unlicense either version 1.0 and later.
