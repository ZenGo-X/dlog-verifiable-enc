# Verifiable Encryption of Discrete Logarithms

Implementation Dlog VE in Javascript (with Rust bindings) on top of the elliptic curve Secp256k1.<br>


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

## Construction
The construction is inspired by [CS03]. 

**Key Generation:** choose random scalar `y` and compute its public key `Y = y*G`

**Encrypt:** For input `(x,Q,Y)` such that `Q = x*G` we want to encrypt `x`:Divide `x` into `m` eqaul small (lets say 8 bit) segments (last segment is padded with zeros). For each segment `k`: compute homomorphic ElGamal encryption: `{D_k ,E_k = [x]_k*G + r_k*Y , r_k * G}` for random `r_k`

**Decrypt:** Given a secret key `y`, for every pair `{D_k ,E_k}` do: 
  1) `[x]_k*G = D_k - y*E_k`
  2) find DLog of  `[x]_k*G`
  
Finally combine all decrypted segments to get `x`

**Prove:** (*)
  1) For each `D_k` the prover publishes a Bulletproof range proof [BBBPWM]. This proves that `D_k` is a Pedersen commitment with value smaller than `2^l` where `l` is the segment size in bits.
  2) For each `k`: The Prover publishes a zero knowledge proof that `{D_k,E_k}` is correct ElGamal encryption, witness is `(x, r_k)`.
  3) The Prover publishes a zero knowledge proof that `{wsum{D_k}, wsum{E_k}}` is correct ElGamal encryption, witness is `(x, wsum{r_k})`. we use `wsum` to note a weighted sum. This sigma protocol also uses `Q` in the statement and the prover shows in zk that DLog of `Q` is the same witness.    


**Verify:** Run the verifer of all the zk proofs. Accept only if all value to true

**(*)** Both 2) and 3) are standatd proof of knowledge sigma protocols, we use Fiat Shamir transforom to get their non interactive versions. The protocols can be found in [Curv](https://github.com/KZen-networks/curv) library([2](https://github.com/KZen-networks/curv/blob/master/src/cryptographic_primitives/proofs/sigma_correct_homomorphic_elgamal_enc.rs#L17),[3](https://github.com/KZen-networks/curv/blob/master/src/cryptographic_primitives/proofs/sigma_correct_homomorphic_elgamal_encryption_of_dlog.rs#L17))

The encryption is done segment-by-segment which enables also a use case of fair swap of secrets. 


## Contact

Feel free to [reach out](mailto:github@kzencorp.com) or join the KZen Research [Telegram](https://t.me/kzen_research) for discussions on code and research.

## References

\[CS03] [
  _Practical Verifiable Encryption and Decryption
   of Discrete Logarithms_
](https://link.springer.com/content/pdf/10.1007/978-3-540-45146-4_8.pdf),
  Jan Camenisch and Victor Shoup, CRYPTO 2003
  
\[BBBPWM] [
  _Bulletproofs: Short Proofs for Confidential Transactions and More_
](https://eprint.iacr.org/2017/1066.pdf),
Benedikt B¨unz, Jonathan Bootle, Dan Boneh, Andrew Poelstra, Pieter Wuille and Greg Maxwell, IEEE S&P 2018
  
