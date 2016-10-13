#include <stdio.h>
#include <string.h>

#include <openssl/engine.h>

#include <openssl/evp.h>

#define NID_id_SIDH 2560

static const char *engine_id = "sidh";
static const char *engine_name = "A openssl engine for SIDH, a post-quantum public key protocol";

static EVP_PKEY_METHOD *pkey_sidh = NULL;

static int sidh_pkey_meth_nids[] = {
    NID_id_SIDH,
    0
};

static void init(void);
static int sidh_pkey_meths(ENGINE *e, EVP_PKEY_METHOD **pmeth, const int **nids, int nid);
static int register_pkey_meth(int id, EVP_PKEY_METHOD **pmeth, int flags);
static int pkey_sidh_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2);
static int pkey_sidh_ec_ctrl(EVP_PKEY_CTX *ctx, const char *type, const char *value);

int sidh_control_func(ENGINE *e, int cmd, long i, void *p, void (*f) (void));

static void init(void)
{
    if(!register_pkey_meth(NID_id_SIDH, &pkey_sidh, 0)) {
        fprintf(stderr, "SIDH engine failed to register id %d\n", NID_id_SIDH);
    }

    //fprintf(stderr, "SIDH engine registered all ids\n");
};

static int sidh_pkey_meths(ENGINE *e, EVP_PKEY_METHOD **pmeth, const int **nids, int nid)
{
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
        EVP_PKEY_meth_set_ctrl(*pmeth, pkey_sidh_ctrl, pkey_sidh_ec_ctrl);
                               
        //EVP_PKEY_meth_set_keygen(*pmeth, NULL, pkey_gost2001cp_keygen);
        //EVP_PKEY_meth_set_derive(*pmeth, pkey_gost_derive_init, pkey_gost_ec_derive);
        //EVP_PKEY_meth_set_paramgen(*pmeth, pkey_gost_paramgen_init, pkey_gost2001_paramgen);
                                   


        //EVP_PKEY_meth_set_init(*pmeth, pkey_gost_init);
        //EVP_PKEY_meth_set_cleanup(*pmeth, pkey_gost_cleanup);
        
        //EVP_PKEY_meth_set_copy(*pmeth, pkey_gost_copy);

        //EVP_PKEY_meth_set_sign(*pmeth, NULL, pkey_gost_ec_cp_sign);
        //EVP_PKEY_meth_set_verify(*pmeth, NULL, pkey_gost_ec_cp_verify);
        //EVP_PKEY_meth_set_encrypt(*pmeth, pkey_gost_encrypt_init, pkey_GOST_ECcp_encrypt);
        //EVP_PKEY_meth_set_decrypt(*pmeth, NULL, pkey_GOST_ECcp_decrypt);

    default:                   /* Unsupported method */
        return 0;
    }

    return 1;
}

int sidh_control_func(ENGINE *e, int cmd, long i, void *p, void (*f) (void))
{
    return -1;
}

static int pkey_sidh_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    return 0;
}

static int pkey_sidh_ec_ctrl(EVP_PKEY_CTX *ctx, const char *type, const char *value)
{
    return 0;
}


static int bind(ENGINE *e, const char *id)
{
  fprintf(stderr, "SIDH engine binding...\n");

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

  loaded = 1;

  if (!ENGINE_set_id(e, engine_id)) {
    fprintf(stderr, "ENGINE_set_id failed\n");
    goto end;
  }
  if (!ENGINE_set_name(e, engine_name)) {
    printf("ENGINE_set_name failed\n");
    goto end;
  }
  if (!ENGINE_set_pkey_meths(e, sidh_pkey_meths)) {
      printf("ENGINE_set_pkey_meths failed\n");
      goto end;
  }

  init();

  ret = 1;
 end:
  return ret;
}

IMPLEMENT_DYNAMIC_BIND_FN(bind)
IMPLEMENT_DYNAMIC_CHECK_FN()
