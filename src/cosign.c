#include <stdio.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

#include "crypto/ec.h"

int co_gen_pubkey(const EC_KEY *key, const EC_POINT *P2, EC_POINT **pP) {
    int ret = 0;
    const BIGNUM *d1 = EC_KEY_get0_private_key(key);
    const EC_GROUP *group = EC_KEY_get0_group(key);
    const EC_POINT *generator = EC_GROUP_get0_generator(group);

    BN_CTX *ctx = NULL;
    EC_POINT *P = NULL;
    EC_POINT *G = NULL;

    P = EC_POINT_new(group);
    G = EC_POINT_new(group);
    ctx = BN_CTX_new();
    if (P == NULL || G == NULL || ctx == NULL) {
        goto done;
    }

    if (!EC_POINT_mul(group, P, NULL, P2, d1, ctx)
            || !EC_POINT_copy(G, generator)
            || !EC_POINT_invert(group, G, ctx)
            || !EC_POINT_add(group, P, P, G, ctx)) {
        goto done;
    }

    *pP = P;
    P = NULL;

    ret = 1;

done:
    BN_CTX_free(ctx);
    EC_POINT_free(P);
    EC_POINT_free(G);
    return ret;
}

int cosign_req1(const EC_GROUP *group, const EC_POINT *P2, BIGNUM **pk1, EC_POINT **pQ1) {
    int ret = 0;
    const BIGNUM *order = EC_GROUP_get0_order(group);

    EC_POINT *k1P2 = NULL;
    BIGNUM *k1 = NULL;

    k1P2 = EC_POINT_new(group);
    k1 = BN_new();
    if (k1 == NULL || k1P2 == NULL) {
        goto done;
    }

    if (!BN_priv_rand_range(k1, order)) {
        goto done;
    }

    if (!EC_POINT_mul(group, k1P2, NULL, P2, k1, NULL)) {
        goto done;
    } 
    *pQ1 = k1P2;
    *pk1 = k1;
    k1 = NULL;
    k1P2 = NULL;

    ret = 1;

done:
    BN_free(k1);
    EC_POINT_free(k1P2);

    return ret;
}

int cosign_rsp2(const EC_KEY *key, const BIGNUM *e, const EC_POINT *Q1, BIGNUM **pr, BIGNUM **ps2) {
    int ret = 0;
    const BIGNUM *d2 = EC_KEY_get0_private_key(key);
    const EC_GROUP *group = EC_KEY_get0_group(key);
    const BIGNUM *order = EC_GROUP_get0_order(group);

    EC_POINT *kG = NULL;
    EC_POINT *k2G = NULL;
    BN_CTX *ctx = NULL;
    BIGNUM *k2 = NULL;
    BIGNUM *rk2 = NULL;
    BIGNUM *r = NULL;
    BIGNUM *s2 = NULL;
    BIGNUM *x1 = NULL;
    BIGNUM *tmp = NULL;

    kG = EC_POINT_new(group);
    k2G = EC_POINT_new(group);
    ctx = BN_CTX_new();
    if (kG == NULL || k2G == NULL || ctx == NULL) {
        goto done;
    }

    BN_CTX_start(ctx);
    k2 = BN_CTX_get(ctx);
    rk2 = BN_CTX_get(ctx);
    x1 = BN_CTX_get(ctx);
    tmp = BN_CTX_get(ctx);
    if (tmp == NULL) {
        goto done;
    }

    r = BN_new();
    s2 = BN_new();
    if (r == NULL || s2 == NULL) {
        goto done;
    }

    for (;;) {
        if (!BN_priv_rand_range(k2, order)) {
            goto done;
        }

        if (!EC_POINT_mul(group, k2G, k2, NULL, NULL, ctx)
                || !EC_POINT_add(group, kG, k2G, Q1, ctx)
                || !EC_POINT_get_affine_coordinates(group, kG, x1, NULL,
                                                    ctx)
                || !BN_mod_add(r, e, x1, order, ctx)) {
            goto done;
        }

        /* try again if r == 0 or r+k2 == n */
        if (BN_is_zero(r))
            continue;

        if (!BN_add(rk2, r, k2)) {
            goto done;
        }

        if (BN_cmp(rk2, order) == 0)
            continue;

        if (!ec_group_do_inverse_ord(group, tmp, d2, ctx)
                || !BN_mod_mul(s2, tmp, rk2, order, ctx)) {
            goto done;
        }

        *pr = r;
        *ps2 = s2;
        r = s2 = NULL;

        ret = 1;
        break;
    }

done:
    BN_free(r);
    BN_free(s2);
    BN_CTX_free(ctx);
    EC_POINT_free(kG);
    EC_POINT_free(k2G);

    return ret;
}

int cosign_req3(const EC_KEY *key, const BIGNUM *k1, const BIGNUM *r, const BIGNUM *s2, BIGNUM **ps){
    int ret = 0;
    const BIGNUM *d1 = EC_KEY_get0_private_key(key);
    const EC_GROUP *group = EC_KEY_get0_group(key);
    const BIGNUM *order = EC_GROUP_get0_order(group);

    BN_CTX *ctx = NULL;
    BIGNUM *s = NULL;
    BIGNUM *tmp = NULL;
    BIGNUM *k1s2 = NULL;

    ctx = BN_CTX_new();
    if (ctx == NULL) {
        goto done;
    }

    BN_CTX_start(ctx);
    k1s2 = BN_CTX_get(ctx);
    tmp = BN_CTX_get(ctx);
    if (tmp == NULL) {
        goto done;
    }

    s = BN_new();
    if (s == NULL) {
        goto done;
    }

    if (!BN_add(k1s2, k1, s2)) {
        goto done;
    }

    if (BN_cmp(k1s2, order) == 0)
        goto done;

    if (!ec_group_do_inverse_ord(group, tmp, d1, ctx)
            || !BN_mod_mul(tmp, tmp, k1s2, order, ctx)
            || !BN_mod_sub(s, tmp, r, order, ctx)) {
        goto done;
    }

    *ps = s;
    s = NULL;

    ret = 1;

done:
    BN_free(s);
    BN_CTX_free(ctx);
    return ret;
}

int cosign_blind_req1(const EC_GROUP *group, const EC_POINT *P2, const EC_POINT *Q2, const BIGNUM *e, BIGNUM **pk1, BIGNUM **pr, BIGNUM **pr1){
    int ret = 0;
    const BIGNUM *order = EC_GROUP_get0_order(group);

    EC_POINT *k3G = NULL;
    BN_CTX *ctx = NULL;
    BIGNUM *k1 = NULL;
    BIGNUM *k3 = NULL;
    BIGNUM *rk3 = NULL;
    BIGNUM *r = NULL;
    BIGNUM *r1 = NULL;
    BIGNUM *x1 = NULL;

    k3G = EC_POINT_new(group);
    ctx = BN_CTX_new();
    if (k3G == NULL || ctx == NULL) {
        goto done;
    }

    BN_CTX_start(ctx);
    k3 = BN_CTX_get(ctx);
    rk3 = BN_CTX_get(ctx);
    x1 = BN_CTX_get(ctx);
    if (x1 == NULL) {
        goto done;
    }

    r = BN_new();
    r1 = BN_new();
    k1 = BN_new();
    if (r == NULL || r1 == NULL || k1 == NULL) {
        goto done;
    }

    for (;;) {
        if (!BN_priv_rand_range(k1, order)) {
            goto done;
        }

        if (!BN_priv_rand_range(k3, order)) {
            goto done;
        }

        if (!EC_POINT_mul(group, k3G, k3, P2, k1, ctx)
                || !EC_POINT_add(group, k3G, k3G, Q2, ctx)
                || !EC_POINT_get_affine_coordinates(group, k3G, x1, NULL, ctx)
                || !BN_mod_add(r, e, x1, order, ctx)) {
            goto done;
        }

        /* try again if r == 0 or r+k3 == n */
        if (BN_is_zero(r))
            continue;

        if (!BN_add(rk3, r, k3)) {
            goto done;
        }

        if (BN_cmp(rk3, order) == 0)
            continue;

        if (!BN_mod_add(r1, r, k3, order, ctx)) {
            goto done;
        }

        *pr = r;
        *pr1 = r1;
        *pk1 = k1;
        r = r1 = k1 = NULL;

        ret = 1;
        break;
    }

done:
    BN_free(r);
    BN_free(r1);
    BN_free(k1);
    BN_CTX_free(ctx);
    EC_POINT_free(k3G);

    return ret;
}

int cosign_blind_rsp2(const EC_KEY *key, const BIGNUM *k2, const BIGNUM *r1, BIGNUM **ps2) {
    int ret = 0;
    const BIGNUM *d2 = EC_KEY_get0_private_key(key);
    const EC_GROUP *group = EC_KEY_get0_group(key);
    const BIGNUM *order = EC_GROUP_get0_order(group);

    BN_CTX *ctx = NULL;
    BIGNUM *s2 = NULL;
    BIGNUM *tmp = NULL;
    BIGNUM *k2r1 = NULL;

    ctx = BN_CTX_new();
    if (ctx == NULL) {
        goto done;
    }

    BN_CTX_start(ctx);
    k2r1 = BN_CTX_get(ctx);
    tmp = BN_CTX_get(ctx);
    if (tmp == NULL) {
        goto done;
    }

    s2 = BN_new();
    if (s2 == NULL) {
        goto done;
    }

    if (!ec_group_do_inverse_ord(group, tmp, d2, ctx)
            || !BN_mod_add(k2r1, k2, r1, order, ctx)
            || !BN_mod_mul(s2, tmp, k2r1, order, ctx)) {
        goto done;
    }

    *ps2 = s2;
    s2 = NULL;

    ret = 1;

done:
    BN_free(s2);
    BN_CTX_free(ctx);
    return ret;   
}

int cosign_blind_req3(const EC_KEY *key, const BIGNUM *k1, const BIGNUM *r, const BIGNUM *s2, BIGNUM **ps) {
    int ret = 0;
    const BIGNUM *d1 = EC_KEY_get0_private_key(key);
    const EC_GROUP *group = EC_KEY_get0_group(key);
    const BIGNUM *order = EC_GROUP_get0_order(group);

    BN_CTX *ctx = NULL;
    BIGNUM *s = NULL;
    BIGNUM *tmp = NULL;
    BIGNUM *k1s2 = NULL;

    ctx = BN_CTX_new();
    if (ctx == NULL) {
        goto done;
    }

    BN_CTX_start(ctx);
    k1s2 = BN_CTX_get(ctx);
    tmp = BN_CTX_get(ctx);
    if (tmp == NULL) {
        goto done;
    }

    s = BN_new();
    if (s == NULL) {
        goto done;
    }

    if (!BN_add(k1s2, k1, s2)) {
        goto done;
    }

    if (BN_cmp(k1s2, order) == 0)
        goto done;

    if (!ec_group_do_inverse_ord(group, tmp, d1, ctx)
            || !BN_mod_mul(tmp, tmp, k1s2, order, ctx)
            || !BN_mod_sub(s, tmp, r, order, ctx)) {
        goto done;
    }

    *ps = s;
    s = NULL;

    ret = 1;

done:
    BN_free(s);
    BN_CTX_free(ctx);
    return ret;
}
