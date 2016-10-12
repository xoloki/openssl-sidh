#include <stdio.h>
#include <string.h>

#include <openssl/engine.h>

#include <openssl/evp.h>

static EVP_PKEY_METHOD pkey_sidh;

static void init(void)
{
};

static int sidh_pkey_meth_nids[] = {
    NID_id_SIDH,
    0
};

static int sidh_pkey_meths(ENGINE *e, EVP_PKEY_METHOD **pmeth, const int **nids, int nid)
{
    if (!pmeth) {
        *nids = sidh_pkey_meth_nids;
        return sizeof(sidh_pkey_meth_nids) / sizeof(sidh_pkey_meth_nids[0]) - 1;
    }
    
    switch (nid) {
    case NID_id_SIDH:
        *pmeth = &pkey_sidh;
        return 1;

    default:;
    }

    *pmeth = NULL;
    return 0;
}
                           

static const char *engine_id = "sidh";
static const char *engine_name = "A openssl engine for SIDH, a post-quantum public key protocol";
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

  loaded = 1;

  if (!ENGINE_set_id(e, engine_id)) {
    fprintf(stderr, "ENGINE_set_id failed\n");
    goto end;
  }
  if (!ENGINE_set_name(e, engine_name)) {
    printf("ENGINE_set_name failed\n");
    goto end;
  }
  if (!ENGINE_set_digests(e, digests)) {
    printf("ENGINE_set_name failed\n");
    goto end;
  }

  init();

  ret = 1;
 end:
  return ret;
}

IMPLEMENT_DYNAMIC_BIND_FN(bind)
IMPLEMENT_DYNAMIC_CHECK_FN()
