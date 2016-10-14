#include <stdio.h>
#include <string.h>

#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "SIDH.h"

#define NID_id_SIDH 2560

static int sidh_pkey_meth_nids[] = {
    NID_id_SIDH,
    0
};

static const char *engine_id = "sidh";
static const char *engine_name = "A openssl engine for SIDH, a post-quantum public key protocol";

static EVP_PKEY_METHOD *pkey_sidh = NULL;

struct sidh_pkey_data {
    PCurveIsogenyStruct curve_isogeny;
};

static int pkey_sidh_init(EVP_PKEY_CTX *ctx);
static int pkey_sidh_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src);
static void pkey_sidh_cleanup(EVP_PKEY_CTX *ctx);
static int sidh_pkey_meths(ENGINE *e, EVP_PKEY_METHOD **pmeth, const int **nids, int nid);
static int register_pkey_meth(int id, EVP_PKEY_METHOD **pmeth, int flags);
static int pkey_sidh_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2);
static int pkey_sidh_ctrl_str(EVP_PKEY_CTX *ctx, const char *type, const char *value);
static int sidh_control_func(ENGINE *e, int cmd, long i, void *p, void (*f) (void));
static int pkey_sidh_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *key);
static int pkey_sidh_paramgen(EVP_PKEY_CTX *ctx, EVP_PKEY *key);
static CRYPTO_STATUS sidh_random_bytes(unsigned int nbytes, unsigned char* random_array);

static int pkey_sidh_init(EVP_PKEY_CTX *ctx)
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
static int pkey_sidh_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src)
{
    struct sidh_pkey_data *dst_data, *src_data;
    if (!pkey_sidh_init(dst)) {
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
static void pkey_sidh_cleanup(EVP_PKEY_CTX *ctx)
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
    //fprintf(stderr, "sidh_pkey_meths %p, %p, %d\n", pmeth, nids, nid);
    if (!pmeth) {
        *nids = sidh_pkey_meth_nids;
        return sizeof(sidh_pkey_meth_nids) / sizeof(sidh_pkey_meth_nids[0]) - 1;
    }
    
    switch (nid) {
    case NID_id_SIDH:
        *pmeth = pkey_sidh;
        return 1;

    default:;
    }

    *pmeth = NULL;
    return 0;
}
                           
static int register_pkey_meth(int id, EVP_PKEY_METHOD **pmeth, int flags)
{
    *pmeth = EVP_PKEY_meth_new(id, flags);
    if (!*pmeth)
        return 0;

    switch (id) {
    case NID_id_SIDH:
        EVP_PKEY_meth_set_ctrl(*pmeth, pkey_sidh_ctrl, pkey_sidh_ctrl_str);
        EVP_PKEY_meth_set_keygen(*pmeth, NULL, pkey_sidh_keygen);
        EVP_PKEY_meth_set_paramgen(*pmeth, NULL, pkey_sidh_paramgen);

        //EVP_PKEY_meth_set_derive(*pmeth, pkey_gost_derive_init, pkey_gost_ec_derive);
        //EVP_PKEY_meth_set_sign(*pmeth, NULL, pkey_gost_ec_cp_sign);
        //EVP_PKEY_meth_set_verify(*pmeth, NULL, pkey_gost_ec_cp_verify);

        break;
        
    default:                   /* Unsupported method */
        return 0;
    }

    EVP_PKEY_meth_set_init(*pmeth, pkey_sidh_init);
    EVP_PKEY_meth_set_cleanup(*pmeth, pkey_sidh_cleanup);
    EVP_PKEY_meth_set_copy(*pmeth, pkey_sidh_copy);

    return 1;
}

static int sidh_control_func(ENGINE *e, int cmd, long i, void *p, void (*f) (void))
{
    fprintf(stderr, "sidh_control_func\n");
    return -1;
}

static int pkey_sidh_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    fprintf(stderr, "pkey_sidh_ctrl\n");
    return 0;
}

static int pkey_sidh_ctrl_str(EVP_PKEY_CTX *ctx, const char *type, const char *value)
{
    fprintf(stderr, "pkey_sidh_ctrl_str\n");
    return 0;
}

static int pkey_sidh_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *key)
{
    unsigned char private_key[1024];
    unsigned char public_key[1024];
    struct sidh_pkey_data *data = EVP_PKEY_CTX_get_data(ctx);

    CRYPTO_STATUS status = KeyGeneration_A(private_key, public_key, data->curve_isogeny);

    return (status == CRYPTO_SUCCESS);
}

static int pkey_sidh_paramgen(EVP_PKEY_CTX *ctx, EVP_PKEY *key)
{
    return 1;
}

static CRYPTO_STATUS sidh_random_bytes(unsigned int num, unsigned char* buf)
{
    return (RAND_bytes(buf, num) == 0);
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
    if (!ENGINE_set_ctrl_function(e, sidh_control_func)) {
        fprintf(stderr, "ENGINE_set_ctrl_func failed\n");
        goto end;
    }
    if(!register_pkey_meth(NID_id_SIDH, &pkey_sidh, 0)) {
        fprintf(stderr, "SIDH engine failed to register id %d\n", NID_id_SIDH);
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
