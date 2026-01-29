## Goals
  - Low overhead way to dectect minTLSVersion + cipher suite + supported groups


## Method
  -  Hook into socketlayer looks at first few bytes of each message
  - determine if tls hello message
  	- if not continue
        - else parse out minVerstionTLS +  cipher suite + curves
