# Experimental SM9 BN256 pairing

`enable-pairing` adds the GM/T 0044.5 SM9 BN curve and R-ate pairing.
It is disabled by default. G1 is an ordinary Tongsuo `EC_GROUP`; G2 and GT
are opaque types declared in `include/openssl/pairing.h`. No existing curve,
SM9 signature/encryption algorithm, EC ElGamal API, or TLS named group is replaced.

## Parameters and encoding

The curve is `y^2 = x^3 + 5` over Fp, with embedding degree 12 and G1 cofactor 1:

```
p = B640000002A3A6F1D603AB4FF58EC74521F2934B1A7AEEDBE56F9B27E351457D
n = B640000002A3A6F1D603AB4FF58EC74449F2934B18EA8BEEE56EE19CD69ECF25
```

The extension tower is Fp2 = Fp[u]/(u^2+2), Fp4 = Fp2[v]/(v^2-u),
Fp12 = Fp4[w]/(w^3-v). G2 is the SM9 sextic twist `y^2 = x^3 + 5u`.
The generators are the SM9 P1/P2 values. `PAIRING_GROUP_new_sm9()` returns an
explicit-parameter group, not a newly allocated OID or a provider key type.

G1 uses 65-byte uncompressed SEC1 encoding. G2 uses 129 bytes:
`04 || x1 || x0 || y1 || y0`, each coefficient being a 32-byte big-endian
integer. GT uses the SM9 384-byte Fp12 encoding: highest tower coefficient
first, recursively (w2, w1, w0; v1, v0; u1, u0).
G2/GT imports validate canonical field coefficients and order-n subgroup
membership. G2 infinity is rejected on the wire. GT identity is valid.
Scalars passed to G2 multiplication / GT exponentiation must be in `[0,n)`.
`PAIRING_GT_cmp()` returns zero for equality and one otherwise.

## Source and license

`sm9_core.c` and `sm9_local.h` are adapted from the GmSSL project, Apache-2.0,
Copyright 2014-2024 The GmSSL Project:

- [sm9_z256.c](https://github.com/guanzhi/GmSSL/blob/24ae482701a7b124826c382fffc55c19f76d475d/src/sm9_z256.c)
- [sm9_z256.h](https://github.com/guanzhi/GmSSL/blob/24ae482701a7b124826c382fffc55c19f76d475d/include/gmssl/sm9_z256.h)
- [upstream license](https://github.com/guanzhi/GmSSL/blob/24ae482701a7b124826c382fffc55c19f76d475d/LICENSE)

Changes: prefix internal symbols with `ossl_`; replace error and endian helpers;
remove random generation, printing, and GmSSL header dependencies; replace the
large generator precomputation table with generic multiplication; allow the
order n as an internal Fp12 exponent for subgroup validation. Only portable C
arithmetic is built. Original copyright and license notices are retained.
`pairing_lib.c` adds Tongsuo allocation, BIGNUM/EC bridging, and input validation.

`test/pairing_test.c` includes the SM9 signature example pairing value from
[upstream sm9test.c](https://github.com/guanzhi/GmSSL/blob/24ae482701a7b124826c382fffc55c19f76d475d/tests/sm9test.c)
(GM/T 0044.2 appendix A), plus bilinearity, inverse, subgroup and encoding checks.
The [SM9 parameter description](https://github.com/riboseinc/rfc-crypto-sm9/blob/master/sections/80-sm9-params.adoc)
is an additional publicly accessible parameter reference.

## Scope

This is a functional pilot backend. Its scalar multiplication and Fp12
exponentiation have data-dependent control flow; this port has **not** made
them constant time. Passing a known-answer vector does not establish side
channel resistance or protocol security. A 256-bit group order alone does not
establish 128-bit security for a pairing target field. Production deployment
requires an independent cryptographic review, side channel hardening, and an
explicit security-level decision by the standard group.
