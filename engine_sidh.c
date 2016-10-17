#include <stdio.h>
#include <string.h>

#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "SIDH.h"

static int sidh_pkey_meth_nids[] = {
    NID_SIDH,
    0
};

static const char *engine_id = "sidh";
static const char *engine_name = "A openssl engine for SIDH, a post-quantum public key protocol";

static EVP_PKEY_METHOD *pmeth_sidh = NULL;
static EVP_PKEY_ASN1_METHOD *ameth_sidh = NULL;

struct sidh_pkey_data {
    PCurveIsogenyStruct curve_isogeny;
    unsigned char private_key[1024];
    unsigned char public_key[1024];
};


static int sidh_control_func(ENGINE *e, int cmd, long i, void *p, void (*f) (void));
static int sidh_ameth_register(int nid, EVP_PKEY_ASN1_METHOD **ameth, const char *pemstr, const char *info);
static int sidh_pmeth_register(int id, EVP_PKEY_METHOD **pmeth, int flags);

static int sidh_pkey_init(EVP_PKEY_CTX *ctx);
static int sidh_pkey_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src);
static void sidh_pkey_cleanup(EVP_PKEY_CTX *ctx);
static int sidh_pkey_meths(ENGINE *e, EVP_PKEY_METHOD **pmeth, const int **nids, int nid);
static int sidh_pkey_asn1_meths(ENGINE *e, EVP_PKEY_ASN1_METHOD **ameth, const int **nids, int nid);
static int sidh_pkey_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2);
static int sidh_pkey_ctrl_str(EVP_PKEY_CTX *ctx, const char *type, const char *value);
static int sidh_pkey_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *key);
static int sidh_pkey_paramgen(EVP_PKEY_CTX *ctx, EVP_PKEY *key);
static void sidh_pkey_free(EVP_PKEY *key);
static int sidh_priv_print(BIO *out, const EVP_PKEY *pkey, int indent, ASN1_PCTX *pctx);
static int sidh_priv_decode(EVP_PKEY *pk, const PKCS8_PRIV_KEY_INFO *p8inf);
static int sidh_priv_encode(PKCS8_PRIV_KEY_INFO *p8, const EVP_PKEY *pk);

static CRYPTO_STATUS sidh_random_bytes(unsigned int nbytes, unsigned char* random_array);

static int sidh_pkey_init(EVP_PKEY_CTX *ctx)
{
    struct sidh_pkey_data *data;
    //EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(ctx);

    data = OPENSSL_malloc(sizeof(*data));
    if (!data) {
        fprintf(stderr, "Unable to malloc sidh_pkey_data struct");
        return 0;
    }

    memset(data, 0, sizeof(*data));
    data->curve_isogeny = SIDH_curve_allocate(&CurveIsogeny_SIDHp751);
    if (!data->curve_isogeny) {
        fprintf(stderr, "Unable to allocate SIDH curve isogeny");
        return 0;
    }

    CRYPTO_STATUS status = SIDH_curve_initialize(data->curve_isogeny, &sidh_random_bytes, &CurveIsogeny_SIDHp751);

    if(status == CRYPTO_SUCCESS) {
        EVP_PKEY_CTX_set_data(ctx, data);
        return 1;
    } else {
        fprintf(stderr, "Unable to initialize curve isogeny: %d\n", (int)status);
        OPENSSL_free(data);
        return 0;
    }
}

/* Copies contents of sidh_pkey_data structure */
static int sidh_pkey_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src)
{
    struct sidh_pkey_data *dst_data, *src_data;
    if (!sidh_pkey_init(dst)) {
        return 0;
    }
    src_data = EVP_PKEY_CTX_get_data(src);
    dst_data = EVP_PKEY_CTX_get_data(dst);
    if (!src_data || !dst_data)
        return 0;

    *dst_data = *src_data;

    if (src_data->curve_isogeny) {
        src_data->curve_isogeny = NULL;
    }
    return 1;
}

/* Frees up sidh_pkey_data structure */
static void sidh_pkey_cleanup(EVP_PKEY_CTX *ctx)
{
    struct sidh_pkey_data *data = EVP_PKEY_CTX_get_data(ctx);
    if (!data)
        return;
    if (data->curve_isogeny)
        SIDH_curve_free(data->curve_isogeny);
    OPENSSL_free(data);
}

static int sidh_pkey_meths(ENGINE *e, EVP_PKEY_METHOD **pmeth, const int **nids, int nid)
{
    fprintf(stderr, "sidh_pkey_meths %p, %p, %d\n", pmeth, nids, nid);
    if (!pmeth) {
        *nids = sidh_pkey_meth_nids;
        return sizeof(sidh_pkey_meth_nids) / sizeof(sidh_pkey_meth_nids[0]) - 1;
    }
    
    switch (nid) {
    case NID_SIDH:
        *pmeth = pmeth_sidh;
        return 1;

    default:;
    }

    *pmeth = NULL;
    return 0;
}
                           
static int sidh_pkey_asn1_meths(ENGINE *e, EVP_PKEY_ASN1_METHOD **ameth, const int **nids, int nid)
{
    fprintf(stderr, "sidh_pkey_asn1_meths %p, %p, %d\n", ameth, nids, nid);
    if (!ameth) {
        *nids = sidh_pkey_meth_nids;
        return sizeof(sidh_pkey_meth_nids) / sizeof(sidh_pkey_meth_nids[0]) - 1;
    }
    
    switch (nid) {
    case NID_SIDH:
        *ameth = ameth_sidh;
        return 1;

    default:;
    }

    *ameth = NULL;
    return 0;
}
                           
static int sidh_pmeth_register(int id, EVP_PKEY_METHOD **pmeth, int flags)
{
    *pmeth = EVP_PKEY_meth_new(id, flags);
    if (!*pmeth)
        return 0;

    switch (id) {
    case NID_SIDH:
        EVP_PKEY_meth_set_ctrl(*pmeth, sidh_pkey_ctrl, sidh_pkey_ctrl_str);
        EVP_PKEY_meth_set_keygen(*pmeth, NULL, sidh_pkey_keygen);
        EVP_PKEY_meth_set_paramgen(*pmeth, NULL, sidh_pkey_paramgen);

        //EVP_PKEY_meth_set_derive(*pmeth, pkey_gost_derive_init, pkey_gost_ec_derive);
        //EVP_PKEY_meth_set_sign(*pmeth, NULL, pkey_gost_ec_cp_sign);
        //EVP_PKEY_meth_set_verify(*pmeth, NULL, pkey_gost_ec_cp_verify);

        break;
        
    default:                   /* Unsupported method */
        return 0;
    }

    EVP_PKEY_meth_set_init(*pmeth, sidh_pkey_init);
    EVP_PKEY_meth_set_cleanup(*pmeth, sidh_pkey_cleanup);
    EVP_PKEY_meth_set_copy(*pmeth, sidh_pkey_copy);

    return 1;
}

static int sidh_ameth_register(int nid, EVP_PKEY_ASN1_METHOD **ameth, const char *pemstr, const char *info)
{
    *ameth = EVP_PKEY_asn1_new(nid, ASN1_PKEY_SIGPARAM_NULL, pemstr, info);
    if (!*ameth)
        return 0;
    switch (nid) {
    case NID_SIDH:
        EVP_PKEY_asn1_set_free(*ameth, sidh_pkey_free);
        EVP_PKEY_asn1_set_private(*ameth,
                                  sidh_priv_decode, sidh_priv_encode,
                                  sidh_priv_print);
        /*
        EVP_PKEY_asn1_set_param(*ameth,
                                gost2001_param_decode, gost2001_param_encode,
                                param_missing_gost_ec, param_copy_gost_ec,
                                param_cmp_gost_ec, param_print_gost_ec);
        EVP_PKEY_asn1_set_public(*ameth,
                                 pub_decode_gost_ec, pub_encode_gost_ec,
                                 pub_cmp_gost_ec, pub_print_gost_ec,
                                 pkey_size_gost, pkey_bits_gost);

        EVP_PKEY_asn1_set_ctrl(*ameth, pkey_ctrl_gost);
        */
        return 1;
    }

    return 0;
}

static int sidh_priv_print(BIO *out, const EVP_PKEY *pkey, int indent,
                           ASN1_PCTX *pctx)
{
    return 0;// print_gost_ec(out, pkey, indent, pctx, 2);
}


static void sidh_pkey_free(EVP_PKEY *key)
{
    //EC_KEY_free(key->pkey.ec);
}

static int sidh_priv_decode(EVP_PKEY *pk, const PKCS8_PRIV_KEY_INFO *p8inf)
{
    fprintf(stderr, "sidh_priv_decode\n");
    return 0;
}

static int sidh_priv_encode(PKCS8_PRIV_KEY_INFO *p8, const EVP_PKEY *pk)
{
/*
    ASN1_OBJECT *algobj = OBJ_nid2obj(EVP_PKEY_base_id(pk));
    ASN1_STRING *params = encode_gost_algor_params(pk);
    unsigned char *buf = NULL;
    int key_len = pkey_bits_gost(pk), i = 0;

    //ASN1_STRING *octet = NULL;
    if (!params) {
        return 0;
    }

    key_len = (key_len < 0) ? 0 : key_len / 8;
    if (key_len == 0 || !(buf = OPENSSL_malloc(key_len))) {
        return 0;
    }

    if (!store_bignum(gost_get0_priv_key(pk), buf, key_len)) {
        OPENSSL_free(buf);
        return 0;
    }

    // Convert buf to Little-endian 
    for (i = 0; i < key_len / 2; i++) {
        unsigned char tmp = buf[i];
        buf[i] = buf[key_len - 1 - i];
        buf[key_len - 1 - i] = tmp;
    }

    octet = ASN1_STRING_new();
    ASN1_OCTET_STRING_set(octet, buf, key_len);

    priv_len = i2d_ASN1_OCTET_STRING(octet, &priv_buf);
    ASN1_STRING_free(octet);
    OPENSSL_free(buf);

    return PKCS8_pkey_set0(p8, algobj, 0, V_ASN1_SEQUENCE, params,
                           priv_buf, priv_len); 
    return PKCS8_pkey_set0(p8, algobj, 0, V_ASN1_SEQUENCE, params,
                           buf, key_len); 
*/
    return 0;
}


static int sidh_control_func(ENGINE *e, int cmd, long i, void *p, void (*f) (void))
{
    fprintf(stderr, "sidh_control_func\n");
    return -1;
}

static int sidh_pkey_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    fprintf(stderr, "sidh_pkey_ctrl\n");
    return 0;
}

static int sidh_pkey_ctrl_str(EVP_PKEY_CTX *ctx, const char *type, const char *value)
{
    fprintf(stderr, "sidh_pkey_ctrl_str\n");
    return 0;
}

static int sidh_pkey_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *key)
{
    struct sidh_pkey_data *data = EVP_PKEY_CTX_get_data(ctx);

    CRYPTO_STATUS status = KeyGeneration_A(data->private_key, data->public_key, data->curve_isogeny);
    if(status != CRYPTO_SUCCESS) {
        fprintf(stderr, "Failed to generate SIDH key: %s\n", SIDH_get_error_message(status));
        return 0;
    }

    return 1;
}

static int sidh_pkey_paramgen(EVP_PKEY_CTX *ctx, EVP_PKEY *key)
{
    return 1;
}

static CRYPTO_STATUS sidh_random_bytes(unsigned int num, unsigned char* buf)
{
    return (RAND_bytes(buf, num) == 1 ? CRYPTO_SUCCESS : CRYPTO_ERROR);
}

static int bind(ENGINE *e, const char *id)
{
    int ret = 0;
    
    static int loaded = 0;
    
    if (id && strcmp(id, engine_id)) {
        fprintf(stderr, "SIDH engine called with the unexpected id %s\n", id);
        fprintf(stderr, "The expected id is %s\n", engine_id);
        goto end;
    }
    
    if (loaded) {
        fprintf(stderr, "SIDH engine already loaded\n");
        goto end;
    }
    if (!ENGINE_set_id(e, engine_id)) {
        fprintf(stderr, "ENGINE_set_id failed\n");
        goto end;
    }
    if (!ENGINE_set_name(e, engine_name)) {
        printf("ENGINE_set_name failed\n");
        goto end;
    }
    if (!ENGINE_set_pkey_meths(e, sidh_pkey_meths)) {
        fprintf(stderr, "ENGINE_set_pkey_meths failed\n");
        goto end;
    }
    if (!ENGINE_set_pkey_asn1_meths(e, sidh_pkey_asn1_meths)) {
        fprintf(stderr, "ENGINE_set_pkey_asn1_meths failed\n");
        goto end;
    }
    if (!ENGINE_set_ctrl_function(e, sidh_control_func)) {
        fprintf(stderr, "ENGINE_set_ctrl_func failed\n");
        goto end;
    }
    if(!sidh_ameth_register(NID_SIDH, &ameth_sidh, "SIDH", "Supersingular Isogeny DH")) {
        fprintf(stderr, "SIDH engine failed to register ameth id %d\n", NID_SIDH);
    }
    if(!sidh_pmeth_register(NID_SIDH, &pmeth_sidh, 0)) {
        fprintf(stderr, "SIDH engine failed to register pmeth id %d\n", NID_SIDH);
    }
    if (!ENGINE_register_pkey_meths(e)) {
        fprintf(stderr, "ENGINE_register_pkey_meths failed\n");
        goto end;
    }

    loaded = 1;
    ret = 1;

 end:
    return ret;
}

IMPLEMENT_DYNAMIC_BIND_FN(bind)
IMPLEMENT_DYNAMIC_CHECK_FN()
