#ifndef __COSIGN_H__
#define __COSIGN_H__

#include <openssl/bn.h>
#include <openssl/ec.h>

int co_gen_pubkey(const EC_KEY *key, const EC_POINT *P2, EC_POINT **pP);
int cosign_req1(const EC_GROUP *group, const EC_POINT *P2, BIGNUM **pk1, EC_POINT **pQ1);
int cosign_rsp2(const EC_KEY *key, const BIGNUM *e, const EC_POINT *Q1, BIGNUM **pr, BIGNUM **ps2);
int cosign_req3(const EC_KEY *key, const BIGNUM *k1, const BIGNUM *r, const BIGNUM *s2, BIGNUM **ps);

int cosign_blind_req1(const EC_GROUP *group, const EC_POINT *P2, const EC_POINT *Q2, const BIGNUM *e, BIGNUM **pk1, BIGNUM **pr, BIGNUM **pr1);
int cosign_blind_rsp2(const EC_KEY *key, const BIGNUM *k2, const BIGNUM *r1, BIGNUM **ps2);
int cosign_blind_req3(const EC_KEY *key, const BIGNUM *k1, const BIGNUM *r, const BIGNUM *s2, BIGNUM **ps);
#endif