# Verifiable Encryption of Discrete Logarithms

Implementation of \[CS03] in Javascript (with Rust bindings) on top of the elliptic curve Secp256k1.<br>
Uses Bulletproofs \[BBBPWM] for Range proofs.


## Installation

1. Install nightly Rust (tested on 1.36.0-nightly).
2. Clone the repoistory:
```sh
$ git clone https://github.com/KZen-networks/dlog-verifiable-enc
$ cd ./dlog-verifiable-enc
$ yarn install
$ yarn run build
```

## Test
```sh
$ mocha
```

\[CS03] [
  _Practical Verifiable Encryption and Decryption
   of Discrete Logarithms_
](https://link.springer.com/content/pdf/10.1007/978-3-540-45146-4_8.pdf),
  Jan Camenisch and Victor Shoup, CRYPTO 2003
  
\[BBBPWM] [
  _Bulletproofs: Short Proofs for Confidential Transactions and More_
](https://eprint.iacr.org/2017/1066.pdf),
Benedikt B¨unz, Jonathan Bootle, Dan Boneh, Andrew Poelstra, Pieter Wuille and Greg Maxwell, IEEE S&P 2018
  
