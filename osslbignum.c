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

#include "osslbignum.h"
#include "nfutil.h"

int osslbn_bignumreceiveupcall(struct NFast_Application *app,
			       struct NFast_Call_Context *cctx,
			       struct NFast_Transaction_Context *tctx,
			       M_Bignum *bignum, int nbytes,
			       const void *source,
			       int msbitfirst, int mswordfirst)
{
  struct NFast_Bignum *BN;
  unsigned char *buf;

  /* nbytes must be a multiple of 4 so the lower two bits must be clear */
  if ((nbytes & 3)) return Status_InvalidParameter;
  BN = (struct NFast_Bignum *)NFastApp_Malloc(app,
					      sizeof(struct NFast_Bignum),
					      cctx,
					      tctx);
  if (!BN) return Status_NoHostMemory;
  BN->bn = NULL;
  /* Now copy contents.  Ensure we end up with a Big-Endian number */
  buf = (unsigned char *) NFastApp_Malloc(app, nbytes, cctx, tctx);
  if (!buf) {
    NFastApp_Free(app, (void *)BN, cctx, tctx);
    return Status_NoHostMemory;
  }
  /* If mswordfirst is already !0, we do not need to swap the
   * words. If mswordfirst == 0, we do.  If msbitfirst is already !0,
   * we do not have to swap the bytes.  If msbitfirst == 0, we do.
   */
  nfutil_copybytes(buf, (const unsigned char *)source, nbytes,
	      mswordfirst == 0 ? 1 : 0, msbitfirst == 0 ? 1 : 0);
  BN->bn = BN_bin2bn(buf, nbytes, NULL);
  /* Free buf as the previous call made a copy. */
  NFastApp_Free(app, (void *)buf, cctx, tctx);
  
  *bignum = BN;
  return Status_OK;
}

int osslbn_bignumsendlenupcall(struct NFast_Application *app,
			       struct NFast_Call_Context *cctx,
			       struct NFast_Transaction_Context *tctx,
			       const M_Bignum *bignum, int *nbytes_r)
{
  if (!bignum) return Status_InvalidParameter;
  *nbytes_r = BN_num_bytes((*bignum)->bn);
  return Status_OK;
}

int osslbn_bignumsendupcall(struct NFast_Application *app,
			    struct NFast_Call_Context *cctx,
			    struct NFast_Transaction_Context *tctx,
			    const M_Bignum *bignum, int nbytes,
			    void *dest, int msbitfirst, int mswordfirst)
{
  int copied;
  struct NFast_Bignum *BN = *bignum;
  unsigned char *buf;

  /* The caller has to have allocated enough memory to hold the entire
     Bignum.  If they don't pass in a sufficiently large buffer, error
     out. */
  if (nbytes != BN_num_bytes(BN->bn)) return Status_InvalidParameter;

  /* Call BN_bn2bin to copy contents in to intermediate buffer, then
     copy into dest with appropriate Endianness.  Ours is always
     Big-endian. */
  buf = (unsigned char *)NFastApp_Malloc(app, nbytes, cctx, tctx);
  if (!buf) return Status_NoHostMemory;
  copied = BN_bn2bin((const BIGNUM *)BN->bn, buf);
  if (copied != nbytes) {
    NFastApp_Free(app, buf, cctx, tctx);
    return Status_Failed;
  }
  /* Internal storage is big-Endian. If the msbitfirst resp.
     mswordfirst are TRUE, no transformation.  If either are FALSE,
     apply that transformation. */
  nfutil_copybytes(dest, (const unsigned char *)buf, nbytes,
		   msbitfirst == 0 ? 1 : 0,
		   mswordfirst == 0 ? 1 : 0);
  
  return Status_OK;
}

void osslbn_bignumfreeupcall(struct NFast_Application *app,
			     struct NFast_Call_Context *cctx,
			     struct NFast_Transaction_Context *tctx,
			     M_Bignum *bignum)
{
  if (!bignum) return;
  BN_clear_free((*bignum)->bn);
  NFastApp_Free(app, (void *)(*bignum), cctx, tctx);
  *bignum = NULL; 
}

int osslbn_bignumformatupcall(struct NFast_Application *app,
			      struct NFast_Call_Context *cctx,
			      struct NFast_Transaction_Context *tctx,
			      int *msbitfirst_io, int *mswordfirst_io)
{
  /* OpenSSL BIGNUMs are always Big-Endian, so tell the caller this */
  *msbitfirst_io=1;
  *mswordfirst_io=1;
  return Status_OK;
}

NFast_BignumUpcalls osslbn_upcalls = {
  osslbn_bignumreceiveupcall, /* NFast_BignumReceiveUpcall_t */
  osslbn_bignumsendlenupcall, /* NFast_BignumSendLenUpcall_t */
  osslbn_bignumsendupcall, /* NFast_BignumSendUpcall_t */
  osslbn_bignumfreeupcall, /* NFast_BignumFreeUpcall_t */
  osslbn_bignumformatupcall  /* NFast_BignumFormatUpcall_t */
};
