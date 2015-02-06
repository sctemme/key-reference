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

#ifndef OSSLBIGNUM_H
#define OSSLBIGNUM_H

#include <nfastapp.h>

#include <openssl/bn.h>

#ifdef __cplusplus
extern "C" {
#endif
  
  struct NFast_Bignum {
    /* Per OpenSSL documentation, its Bignums are always
     * Big-Endian. This means that:
     * 
     * The Most Significant Word comes FIRST and
     * The Most Significant Bit  comes FIRST. 
     */
    BIGNUM *bn;
  };
  
  extern int osslbn_bignumreceiveupcall(struct NFast_Application *app,
					struct NFast_Call_Context *cctx,
					struct NFast_Transaction_Context *tctx,
					M_Bignum *bignum, int nbytes,
					const void *source,
					int msbitfirst, int mswordfirst);

  extern int osslbn_bignumsendlenupcall(struct NFast_Application *app,
					struct NFast_Call_Context *cctx,
					struct NFast_Transaction_Context *tctx,
					const M_Bignum *bignum, int *nbytes_r);

  extern int osslbn_bignumsendupcall(struct NFast_Application *app,
				     struct NFast_Call_Context *cctx,
				     struct NFast_Transaction_Context *tctx,
				     const M_Bignum *bignum, int nbytes,
				     void *dest, int msbitfirst, int mswordfirst);

  extern void osslbn_bignumfreeupcall(struct NFast_Application *app,
				      struct NFast_Call_Context *cctx,
				      struct NFast_Transaction_Context *tctx,
				      M_Bignum *bignum);

  extern int osslbn_bignumformatupcall(struct NFast_Application *app,
				       struct NFast_Call_Context *cctx,
				       struct NFast_Transaction_Context *tctx,
				       int *msbitfirst_io, int *mswordfirst_io);


  extern NFast_BignumUpcalls osslbn_upcalls;

#ifdef __cplusplus
}
#endif

/* OSSLBIGNUM_H */
#endif
