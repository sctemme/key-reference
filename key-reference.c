/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Sander Temme
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <errno.h>
#include <string.h>
#include <strings.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include <nfkm.h>
#include "osslbignum.h"

#define BUGOUT(rc, text) if ((rc)) {		\
    NFast_Perror((text), (rc));			\
    goto cleanup;				\
  }

/*
static const char *hash2hex(const M_Hash *hash) {
  static char buf[sizeof(hash->bytes)*2+1];

  char *p;
  int i;

  for (i=0, p=buf; i<sizeof(hash->bytes); i++, p+=2)
    sprintf(p, "%02x", hash->bytes[i]);
  return buf;
}
*/

/* Print the OpenSSL error stack to stderr */
void ossl_print_errors(void);

void ossl_print_errors(void)
{
  unsigned long error;
  char errorstring[120];
  char *displaystr = NULL;

  ERR_load_crypto_strings();

  while ((error = ERR_get_error()) != 0) {
    displaystr = ERR_error_string(error, errorstring);
    fprintf(stderr, "%s\n", displaystr);
  }
}

/* Make a tag of suitable length with the NFKM Hash of the key in it */
BIGNUM *make_tag(struct NFast_Application *app,
		 struct NFast_Call_Context *cctx,
		 struct NFast_Transaction_Context *tctx,
		 M_KeyHash *nfkmhash, int len);

/* Identifier at the start of the tag.  Length should be 10. */
#define TAG "NFKM Hash:"

BIGNUM *make_tag(struct NFast_Application *app,
		 struct NFast_Call_Context *cctx,
		 struct NFast_Transaction_Context *tctx,
		 M_KeyHash *nfkmhash, int len) {
  BIGNUM *bn = NULL;
  const unsigned char *buf;
  unsigned char *pos;
  int chars;

  /* Length must be a multiple of 4 */
  if ((len & 3) != 0) return NULL;
  /* Leading tag is 11 bytes including trailing \0 left by sprintf.
     NFKM Hash is 20 bytes.  Let's add a trailing \0 after the NFKM
     hash.  This means our minimum length is 32 bytes. */
  if (len < 32) return NULL;

  buf = (const unsigned char *)NFastApp_Malloc(app, len, cctx, tctx);
  if (buf == NULL) return NULL;
  /* Mutable copy of buf, and the pointer we will use to poke values
     into the buffer */
  pos = (unsigned char *)buf;

  /* Whimsy: set all bytes to 42 (0x2a, which is the universal Answer to the
     question of Life, the Universe, and Everything) so the unused
     ones are easily distinguished. */
  memset(pos, 42, len);

  chars = sprintf((char *)pos, TAG);
  if (chars == 0) return NULL;
  pos += chars;
  ++pos; /* Skip the trailing \0 of the tag string. */

  /* Hardcoding the length of the NFKM Hash construct to 20: this is
     safe (safer than a potential buffer overrun). */
  memcpy(pos, nfkmhash->bytes, 20);
  pos += 20;
  *pos = 0; /* Trailing zero after the NFKM Hash */

  /* Now stuff the result into a BIGNUM */
  bn = BN_bin2bn(buf, len, bn);

  return bn;
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
  EVP_PKEY *pkey;
  RSA *rsa;
  DSA *dsa;
  EC_KEY *ec;
  EC_GROUP *ecgroup;
  M_ECPoint mpublic;
  EC_POINT *ecpublic;
  BN_CTX *bnctx;
  BIGNUM *tag;
  char *outname;
  FILE *outfile = NULL;
  char *errstr;

  /* We need two arguments: key appname and ident. Without both we
     cannot proceed. */
  if (argc != 4) {
    fprintf(stderr, "Usage: %s appname ident outfilename\n", argv[0]);
    goto cleanup;
  }
  keyident.appname = argv[1];
  keyident.ident = argv[2];
  outname = argv[3];

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

  pkey = EVP_PKEY_new();
  if (pkey == NULL) {
    ossl_print_errors();
    goto cleanup;
  }

  switch (keytype) {
  case KeyType_RSAPublic:
    rsa = RSA_new();
    /* Assign the appropriate key values: n, e and a dummy d. */
    rsa->n = reply.reply.export.data.data.rsapublic.n->bn;
    rsa->e = reply.reply.export.data.data.rsapublic.e->bn;
    /* The private exponent length is half the key modulus
       size. Passing in bytes not bits. */
    tag = make_tag(nfapp, NULL, NULL, &keyhash, keylength / (2*8));
    rsa->d = tag;
    /* Contrary to RSA(3) documentation, openssl rsa won't read the
       PEM file unless p is set.  Set it to the key modulus just like
       the embedsavefile does. */
    rsa->p = reply.reply.export.data.data.rsapublic.n->bn;
    /* Same for q: set to 1 just like the embedsavefile. Note this
       utility function returns a const BIGNUM * but I don't think we
       will attempt to change its value so discarding the constness
       should be safe.  */
    rsa->q = (BIGNUM *)BN_value_one();
    rsa->dmp1 = (BIGNUM *)BN_value_one();
    rsa->dmq1 = (BIGNUM *)BN_value_one();
    /* Finally set the coefficient value to the tag */
    rsa->iqmp = tag;
    status = EVP_PKEY_assign_RSA(pkey, rsa);
    if (status == 0) {
      fprintf(stderr, "Error assigning RSA key.\n");
      ossl_print_errors();
      goto cleanup;
    }
    break;
  case KeyType_DSAPublic:
    dsa = DSA_new();
    /* This is pretty straightforward */
    dsa->p = reply.reply.export.data.data.dsapublic.dlg.p->bn;
    dsa->q = reply.reply.export.data.data.dsapublic.dlg.q->bn;
    dsa->g = reply.reply.export.data.data.dsapublic.dlg.g->bn;
    /* Private key value is same lenght as the key, but of course we
       have to specify bytes not bits. */
    tag = make_tag(nfapp, NULL, NULL, &keyhash, keylength / 8);
    dsa->priv_key = tag;
    dsa->pub_key = reply.reply.export.data.data.dsapublic.y->bn;
    status = EVP_PKEY_assign_DSA(pkey, dsa);
    if (status == 0) {
      fprintf(stderr, "Error assigning DSA key.\n");
      ossl_print_errors();
      goto cleanup;
    }
    break;
  case KeyType_ECPublic:
  case KeyType_ECDSAPublic:
    ec = EC_KEY_new();
    switch (reply.reply.export.data.data.ecpublic.curve.name) {
      /* It appears Red Hat strips out most Named Curves from their
       * system-provided OpenSSL.  The OpenSSL found in Fedora 18 only
       * knows the following curves:
       *
       * openssl ecparam -list_curves
       *   secp384r1 : NIST/SECG curve over a 384 bit prime field
       *   secp521r1 : NIST/SECG curve over a 521 bit prime field
       *   prime256v1: X9.62/SECG curve over a 256 bit prime field
       *
       * prime256v1 is the same as our NISTP256, so we can support
       * that.  Others will likely require redefinition of the named
       * curve in our code since nCore does not supply parameter
       * values for named curves.
       */

      /* The generatekey utility supports for app type PKCS#11 and key
	 type ECDSA the following curves: NISTP192, NISTP224,
	 NISTP256, NISTP384, NISTP521, NISTB163, NISTB233, NISTB283,
	 NISTB409, NISTB571, NISTK163, NISTK233, NISTK283, NISTK409,
	 NISTK571, ANSIB163v1, ANSIB191v1, SECP160r1, CustomLCF.  Oh
	 and the last one errors out... Oops generatekey. */
    case ECName_NISTP256:
      ecgroup = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
      if (ecgroup == NULL) {
	fprintf(stderr, "Error obtaining EC Group\n");
	ossl_print_errors();
	goto cleanup;
      }
      break;
    default:
      fprintf(stderr, "Unsupported Elliptic Curve: %s\n",
	      NF_Lookup(reply.reply.export.data.data.ecpublic.curve.name,
			NF_ECName_enumtable));
      goto cleanup;
    }
    status = EC_KEY_set_group(ec, ecgroup);
    if (status == 0) {
      fprintf(stderr, "Error assigning Group to EC Key\n");
      ossl_print_errors();
      goto cleanup;
    }

    /* Set the private key value */
    tag = make_tag(nfapp, NULL, NULL, &keyhash, keylength / 8);
    status = EC_KEY_set_private_key(ec, (const BIGNUM *)tag);
    if (status == 0) {
      fprintf(stderr, "Error setting EC private key value\n");
      ossl_print_errors();
      goto cleanup;
    }
    /* Construct the public key and set it */
    mpublic = reply.reply.export.data.data.ecpublic.Q;
    ecpublic = EC_POINT_new((const EC_GROUP *)ecgroup);
    if (mpublic.flags & ECPoint_flags_Infinity) {
      /* I don't know if key points are ever at Infinity. */
      status = EC_POINT_set_to_infinity((const EC_GROUP *)ecgroup,
					ecpublic);
      if (status == 0) {
	fprintf(stderr, "Error setting Public Key point to infinity\n");
	ossl_print_errors();
	goto cleanup;
      }
    } else {
      /* TODO once we support non-primary curves, we need to
	 distinguish the curve type here and call the right assignment
	 function */
      bnctx = BN_CTX_new();
      status = EC_POINT_set_affine_coordinates_GFp((const EC_GROUP *)ecgroup,
						   ecpublic,
						   mpublic.x->bn,
						   mpublic.y->bn,
						   bnctx);
      if (status == 0) {
	fprintf(stderr, "Error setting public key point coordinates\n");
	ossl_print_errors();
	goto cleanup;
      }
    }
    status = EC_KEY_set_public_key(ec, (const EC_POINT *)ecpublic);
    if (status == 0) {
      fprintf(stderr, "Error setting public key\n");
      ossl_print_errors();
      goto cleanup;
    }

    status = EVP_PKEY_assign_EC_KEY(pkey, ec);
    if (status == 0) {
      fprintf(stderr, "Error assigning EC key.\n");
      ossl_print_errors();
      goto cleanup;
    }
    break;
  default:
    fprintf(stderr, "Unsupported key type: %s\n",
	    NF_Lookup(keytype, NF_KeyType_enumtable));
    goto cleanup;
  }

  outfile = fopen(outname, "w");
  if (outfile == NULL) {
    errstr = strerror(errno);
    fprintf(stderr, "Error opening output file for writing: %s\n", errstr);
    goto cleanup;
  }
  status = PEM_write_PKCS8PrivateKey(outfile, pkey, NULL, NULL, 0, NULL, NULL);
  if (status == 0) {
    /* Unlike everywhere else on the system, OpenSSL uses 1 for
       success and 0 for errors. */
    fprintf(stderr, "Error writing output file\n");
    ossl_print_errors();
    goto cleanup;
  }

  status = fclose(outfile);
  if (status != 0) {
    errstr = strerror(errno);
    fprintf(stderr, "Error closing output file: %s\n", errstr);
    goto cleanup;
  }

  return 0;

 cleanup:
  /* We got here because something errored out.  Do any cleanup
     necessary before proceeding.  NOTE: if we're just falling out of
     the bottom of the main() function, we don't need to clean up
     anything.  If this code is pasted into some other context, we
     will. */
  if (outfile) {
    /* Ignore int result b/c we're done. */
    fclose(outfile);
  }

  return 1;
}
