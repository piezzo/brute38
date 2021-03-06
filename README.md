## brute38

BIP38 brute force password cracker, written in Go

[![Build Status](https://travis-ci.org/piezzo/timestamp.svg?branch=master)](https://travis-ci.org/piezzo/brute38)

Based on Charlie Hothersall-Thomas' implementation, but added features, bugs fixed,
and expanded with more command-line options and better support for variable-length passwords.

Latest additions are mostly statistics and ETA calculations.

See Charlie Hothersall-Thomas' original implementation  https://github.com/chigley/bip38 and Calin Culian's implementation which was the base for this fork at https://github.com/cculianu/brute38

## Requires:

- Go Language

## Installation/Compilation:
```
go get

go build

./brute38
```
The above assumes you have Go set up properly and you copied the code into your GOPATH/src somewhere.

If this got you access to your long-lost ridiculous wealth, you know how to reach me. 3CNFhj357vEoYXopEHZ1HuzGtb9qopXi3Y :)


## License

The program is released under the terms of the MIT license. See [LICENSE](LICENSE) for more information.
