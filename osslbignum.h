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
