# Journal
## 4.21
Problems come to eCaputure. It puts hex data into fifo rather than raw http data.
### TODO on eCapture
- Only retain tls function
- Remove cobra
- Optimize fifo behaviour(initialize at the entry)
- Get the raw data


## 4.20
HTTP TEST:
- Capture **JPEG**:Success (remember to turn on **DOTALL**)
- Capture multiple regex in one request:Success
HTTPS TEST:
- ***Cannot capture jpeg traffic***
### TODO
- Separate regex matchings of http and https by running them in two threads
- Dig into eCapture to find out why it's unable to capture jpeg traffic