#include <stdio.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <crypto/sm2.h>

#include "cosign.h"

int cosign() {
    int ret = -1;
    int siglen = 0;

    unsigned char *p = NULL;
    unsigned char e[32] = { 1 };
    unsigned char sig[72] = {0};

    ECDSA_SIG *ecdsa = NULL;
    EC_POINT *P = NULL, *Q1 = NULL;
    EC_KEY *ec2 = NULL, *ec1 = NULL, *ec = NULL;
    BIGNUM *bn_e = NULL, *bn_k1 = NULL, *bn_r = NULL, *bn_s2 = NULL, *bn_s = NULL;

    ec1 = EC_KEY_new_by_curve_name(NID_sm2);
    ec2 = EC_KEY_new_by_curve_name(NID_sm2);
    if (ec1 == NULL || ec2 == NULL) {
        goto done;
    }

    ret = EC_KEY_generate_key(ec1);
    if (ret != 1) {
        goto done;
    }

    ret = EC_KEY_generate_key(ec2);
    if (ret != 1) {
        goto done;
    }

    ret = co_gen_pubkey(ec1, EC_KEY_get0_public_key(ec2), &P);
    if (ret != 1) {
        goto done;
    }

    ret = cosign_req1(EC_KEY_get0_group(ec1), EC_KEY_get0_public_key(ec2), &bn_k1, &Q1);
    if (ret != 1) {
        goto done;
    }

    bn_e = BN_bin2bn(e, 32, NULL);
    if (bn_e == NULL) {
        goto done;
    }

    ret = cosign_rsp2(ec2, bn_e, Q1, &bn_r, &bn_s2);
    if (ret != 1) {
        goto done;
    }

    ret = co_sign_req_s(ec1,bn_k1, bn_r, bn_s2, &bn_s);
    if (ret != 1) {
        goto done;
    }

    ecdsa = ECDSA_SIG_new();
    if (ecdsa == NULL) {
        goto done;
    }

    ECDSA_SIG_set0(ecdsa, bn_r, bn_s);
    bn_r = bn_s = NULL;

    p = sig;
    siglen = i2d_ECDSA_SIG(ecdsa, &p);
    if (siglen <= 0) {
        goto done;
    }

    ec = EC_KEY_new_by_curve_name(NID_sm2);
    if (ec == NULL) {
        goto done;
    }

    ret = EC_KEY_set_public_key(ec, P);
    if (ret != 1) {
        goto done;
    }

    ret = sm2_verify(e, 32, sig, siglen, ec);
    if (ret != 1) {
        goto done;
    }

    ret = 1;
done:

    EC_KEY_free(ec);
    EC_KEY_free(ec1);
    EC_KEY_free(ec2);
    EC_POINT_free(Q1);
    EC_POINT_free(P);
    BN_free(bn_e);
    BN_free(bn_s2);
    ECDSA_SIG_free(ecdsa);

    return ret;
}

int cosign_blind() {
    int ret = -1;
    int siglen = 0;

    unsigned char *p = NULL;
    unsigned char e[32] = { 1 };
    unsigned char sig[72] = {0};

    ECDSA_SIG *ecdsa = NULL;
    EC_POINT *P = NULL, *Q1 = NULL;
    EC_KEY *ec2 = NULL, *ec1 = NULL, *ec = NULL, *k2 = NULL;
    BIGNUM *bn_e = NULL, *bn_k1 = NULL, *bn_r = NULL, *bn_r1 = NULL, *bn_s2 = NULL, *bn_s = NULL;

    ec1 = EC_KEY_new_by_curve_name(NID_sm2);
    ec2 = EC_KEY_new_by_curve_name(NID_sm2);
    k2 = EC_KEY_new_by_curve_name(NID_sm2);
    if (ec1 == NULL || ec2 == NULL || k2 == NULL) {
        goto done;
    }

    ret = EC_KEY_generate_key(ec1);
    if (ret != 1) {
        goto done;
    }

    ret = EC_KEY_generate_key(ec2);
    if (ret != 1) {
        goto done;
    }

    ret = EC_KEY_generate_key(k2);
    if (ret != 1) {
        goto done;
    }

    ret = co_gen_pubkey(ec1, EC_KEY_get0_public_key(ec2), &P);
    if (ret != 1) {
        goto done;
    }

    bn_e = BN_bin2bn(e, 32, NULL);
    if (bn_e == NULL) {
        goto done;
    }

    ret = cosign_blind_req1(EC_KEY_get0_group(ec1), EC_KEY_get0_public_key(ec2), EC_KEY_get0_public_key(k2), bn_e, &bn_k1, &bn_r, &bn_r1);
    if (ret != 1) {
        goto done;
    }

    ret = cosign_blind_rsp2(ec2, EC_KEY_get0_private_key(k2), bn_r1, &bn_s2);
    if (ret != 1) {
        goto done;
    }

    ret = cosign_blind_req3(ec1,bn_k1, bn_r, bn_s2, &bn_s);
    if (ret != 1) {
        goto done;
    }

    ecdsa = ECDSA_SIG_new();
    if (ecdsa == NULL) {
        goto done;
    }

    ECDSA_SIG_set0(ecdsa, bn_r, bn_s);
    bn_r = bn_s = NULL;

    p = sig;
    siglen = i2d_ECDSA_SIG(ecdsa, &p);
    if (siglen <= 0) {
        goto done;
    }

    ec = EC_KEY_new_by_curve_name(NID_sm2);
    if (ec == NULL) {
        goto done;
    }

    ret = EC_KEY_set_public_key(ec, P);
    if (ret != 1) {
        goto done;
    }

    ret = sm2_verify(e, 32, sig, siglen, ec);
    if (ret != 1) {
        goto done;
    }

    ret = 1;

done:
    EC_KEY_free(ec);
    EC_KEY_free(ec1);
    EC_KEY_free(ec2);
    EC_POINT_free(Q1);
    EC_POINT_free(P);
    BN_free(bn_e);
    BN_free(bn_s2);
    ECDSA_SIG_free(ecdsa);

    return ret;
}

int main()
{
    int ret = -1;

    ret = cosign();
    if (ret != 1) {
        goto done;
    }

    ret = cosign_blind();
    if (ret != 1) {
        goto done;
    }

    ret = 0;
done:

    return ret;
}