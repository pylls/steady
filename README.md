# Steady: A simple end-to-end secure logging system
A golang implementation of a proof-of-concept Steady relay and simple echo collector.
For the corresponding Steady device please see the [C implementation](https://github.com/pylls/steady-c).

### Brief instructions to run
1. go get github.com/pylls/steady
2. run steady-relay
3. run steady-make-device
4. copy test.device to the device folder of the [C implementation](https://github.com/pylls/steady-c)
5. build and run the [C demo device](https://github.com/pylls/steady-c)
6. run steady-echo-collector to read from the relay

### Paper
[https://eprint.iacr.org/2018/737](https://eprint.iacr.org/2018/737)

### License
Apache 2.0
