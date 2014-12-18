#include <string.h>
#include <strings.h>

#include <nfkm.h>
#include "osslbignum.h"

#define BUGOUT(rc, text) if ((rc)) {			\
    NFast_Perror((text), (rc));				\
    goto cleanup;					\
  }

static const char *hash2hex(const M_Hash *hash) {
  static char buf[sizeof(hash->bytes)*2+1];

  char *p;
  int i;

  for (i=0, p=buf; i<sizeof(hash->bytes); i++, p+=2)
    sprintf(p, "%02x", hash->bytes[i]);
  return buf;
}

int main(int argc, char *argv[])
{
  NFast_AppHandle nfapp;
  NFastAppInitArgs nfargs;
  NFastApp_Connection nfconn;
  NFKM_WorldInfo *world;
  NFKM_KeyIdent keyident;
  NFKM_Key *keyinfo;
  NFKM_ModuleInfo *moduleinfo;
  M_KeyID keyid;
  M_Command cmd;
  M_Reply reply;
  M_KeyType keytype;
  M_Word keylength;
  M_KeyHash keyhash;
  int status;

  /* We need two arguments: key appname and ident. Without both we
     cannot proceed. */
  if (argc != 3) {
    fprintf(stderr, "Usage: %s appname ident\n", argv[0]);
    goto cleanup;
  }
  keyident.appname = argv[1];
  keyident.ident = argv[2];

  /* For now, zero out the entire args structure.  We will add upcalls
     as we find them necessary */
  bzero(&nfargs, sizeof(nfargs));
  nfargs.flags = NFAPP_IF_BIGNUM;
  nfargs.bignumupcalls = &osslbn_upcalls;

  status = NFastApp_InitEx(&nfapp, &nfargs, NULL);
  BUGOUT(status, "error calling NFastApp_InitEx");

  world = NULL;
  status = NFKM_getinfo(nfapp, &world, NULL);
  BUGOUT(status, "error calling NFKM_getinfo");

  status = NFastApp_Connect(nfapp, &nfconn, 0, NULL);
  BUGOUT(status, "error calling NFastApp_Connect");

  /* Find the key in the file system and make sure it exists. */
  status = NFKM_findkey(nfapp, keyident, &keyinfo, NULL);
  BUGOUT(status, "error calling NFKM_findkey");

  if (!keyinfo) {
  fprintf(stderr, "Key does not exist:\napp: %s ident: %s\n",
    keyident.appname, keyident.ident);
  goto cleanup;
}
  if (!keyinfo->pubblob.len) {
  /* Nefarious caller tried to slip us a symmetric key with no public blob */
  fprintf(stderr, "Key does not have a public half!\n");
  goto cleanup;
}

  /* Now find a suitable module to load the key onto.  We don't care
     which of our modules gets to do this, as long as it's Usable */
  status = NFKM_getusablemodule(world, 0, &moduleinfo);
  BUGOUT(status, "error finding Usable module");

  status = NFKM_cmd_loadblob(nfapp, nfconn,
    moduleinfo->module,
    &keyinfo->pubblob,
    0,
    &keyid,
    "loading public key blob",
    NULL);
  BUGOUT(status, "error loading public key");

  /* There is no NFKM function for GetKeyInfoEx, so we have to drop
     down to nCore for this one */
  bzero(&cmd, sizeof(cmd));
  bzero(&reply, sizeof(reply));
  cmd.cmd = Cmd_GetKeyInfoEx;
  cmd.args.getkeyinfoex.key = keyid;
  status = NFastApp_Transact(nfconn, NULL, &cmd, &reply, 0);
  BUGOUT(status, "error getting key information");
  BUGOUT(reply.status, "error in key information");
  keytype = reply.reply.getkeyinfoex.type;
  keylength = reply.reply.getkeyinfoex.length;
  keyhash = reply.reply.getkeyinfoex.hash;

  /* Now get the public key data */
  bzero(&cmd, sizeof(cmd));
  bzero(&reply, sizeof(reply));
  cmd.cmd = Cmd_Export;
  cmd.args.export.key = keyid;
  status = NFastApp_Transact(nfconn, NULL, &cmd, &reply, 0);
  BUGOUT(status, "error exporting public key data");
  BUGOUT(reply.status, "error in exported public key data");

  /* Key data will be in reply.reply.export.data, and is wildly
     different depending on key type.  Of course the same applies to
     what we will need to do with the key data in OpenSSL. */

  fprintf(stdout, "Key type is %s\n", NF_Lookup(keytype, NF_KeyType_enumtable));
  fprintf(stdout, "Key length is %d\n", keylength);
  fprintf(stdout, "Key hash is %s\n", hash2hex(&keyhash));
  return 0;

 cleanup:
  /* We got here because something errored out.  Do any cleanup
     necessary before proceeding.  NOTE: if we're just falling out of
     the bottom of the main() function, we don't need to clean up
     anything.  If this code is pasted into some other context, we
     will. */
  return 1;
}
