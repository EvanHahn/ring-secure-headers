# ring-secure-headers

Help secure your Ring apps by setting various HTTP headers. It’s not a silver bullet, but it can help! Inspired by [Helmet](https://helmetjs.github.io/) for Node.js.

## Usage

ring-secure-headers is made up of several Ring middleware. You can learn more about this on the [Ring wiki](https://github.com/ring-clojure/ring/wiki/Concepts#middleware).

### Expect-CT

The `Expect-CT` HTTP header tells browsers to expect Certificate Transparency. For more about Certificate Transparency and this header, see [this blog post](https://scotthelme.co.uk/a-new-security-header-expect-ct/) and the [in-progress spec](https://datatracker.ietf.org/doc/draft-stark-expect-ct).

```clojure
(require '[ring-secure-headers.core :as security-headers])

; Sets Expect-CT: max-age=123
(security-headers/expect-ct my-handler {:max-age 123})

; Sets Expect-CT: enforce; max-age=123
(security-headers/expect-ct my-handler {:max-age 123
                                        :enforce? true})

; Sets Expect-CT: enforce; max-age=30; report-uri="https://example.com/report"
(security-headers/expect-ct my-handler {:max-age 30
                                        :enforce? true
                                        :report-uri "https://example.com/report"})
```

## License

Copyright © 2017 Evan Hahn

Distributed under the Unlicense either version 1.0 and later.
