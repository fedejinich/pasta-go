# pasta-go

An experimental implementation of the [PASTA](https://eprint.iacr.org/2021/731.pdf) symmetric cipher in `go`.

### Cipher Setup

```
- Secret key size: 256
- Plaintext size: 128
- Ciphertext size: 128
- Rounds: 3
```
## Prerequisites

- Go version 1.13 or higher

## Install

To get a local copy of the code, clone the repository:

```bash
$ git clone https://github.com/<username>/pasta-go.git
```

## Build

```
go build -o pasta.a
```

## Test

```
go test
```
