/** \file simplebignum.h Simple bignum support
 *
 * Illustrates simple easy-to-use bignumber format. This provides a
 * definition of the \ref NFast_Bignum structure which can be used
 * in applications which do not already have an equivalent structure
 * defined.
 *
 * See also:
 * - \ref nfastapp.h
 * - \ref gsbignum
 */
/* Copyright 1999-2002 nCipher Corporation Limited.
*
* This example source code is provided for your information and
* assistance.  See the file LICENCE.TXT for details and the
* terms and conditions of the licence which governs the use of the
* source code. By using such source code you will be accepting these
* terms and conditions.  If you do not wish to accept these terms and
* conditions, DO NOT OPEN THE FILE OR USE THE SOURCE CODE.
*
* Note that there is NO WARRANTY.
*
*/

#ifndef SIMPLEBIGNUM_H
#define SIMPLEBIGNUM_H

#include "nfastapp.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef MAXBIGNUMBITS
/** Maximum size of a bignum in bits */
#define MAXBIGNUMBITS	16384
#endif

/** Structure of a bignum
 *
 * \ref M_Bignum will be a pointer to this structure. */
struct NFast_Bignum {
  /** Byte order
   *
   * If this is set then each 32-bit word in the bignum is big-endian
   * (most-significant byte first); otherwise it is little-endian
   * (least-significant byte first). */
  int msb_first;
  /** Word order
   *
   * If this is set then 32-bit words in the bignum are in big-endian order
   * (most-significant word first); otherwise they are in little-endian
   * order (least-significant words first).
   */
  int msw_first;
  /** Number of bytes */
  int nbytes;
  /** Bignum data
   *
   * Only the first \a nbytes are used. */
  unsigned char bytes[MAXBIGNUMBITS/8];
};

/* Bignum send & receive upcalls -------------------------- */

/* As well as being used directly as upcalls,
   these can be used to create bignums from data blocks and
   extract data from bignums.
 */

/** Bignum receive upcall
 *
 * See \ref NFast_BignumReceiveUpcall_t */
extern int sbn_bignumreceiveupcall(struct NFast_Application *app,
                               struct NFast_Call_Context *cctx,
                               struct NFast_Transaction_Context *tctx,
                               M_Bignum *bignum, int nbytes,
                               const void *source,
                               int msbitfirst, int mswordfirst);


/** Bignum send-length upcall
 *
 * See \ref NFast_BignumSendLenUpcall_t */
extern int sbn_bignumsendlenupcall(struct NFast_Application *app,
                               struct NFast_Call_Context *cctx,
                               struct NFast_Transaction_Context *tctx,
                               const M_Bignum *bignum, int *nbytes_r);

/** Bignum send upcall
 *
 * See \ref NFast_BignumSendUpcall_t */
extern int sbn_bignumsendupcall(struct NFast_Application *app,
                            struct NFast_Call_Context *cctx,
                            struct NFast_Transaction_Context *tctx,
                            const M_Bignum *bignum, int nbytes,
                            void *dest, int msbitfirst, int mswordfirst);


/** Free bignum upcall
 *
 * See \ref NFast_BignumFreeUpcall_t */
extern void sbn_bignumfreeupcall(struct NFast_Application *app,
                             struct NFast_Call_Context *cctx,
                             struct NFast_Transaction_Context *tctx,
                             M_Bignum *bignum);

/** Bignum format upcall
 *
 * See \ref NFast_BignumFormatUpcall_t */
extern int sbn_bignumformatupcall(struct NFast_Application *app,
                              struct NFast_Call_Context *cctx,
                              struct NFast_Transaction_Context *tctx,
                              int *msbitfirst_io, int *mswordfirst_io);

/** Structure containing bignum upcalls
 *
 * See \ref NFastAppInitArgs and \ref NFAPP_IF_BIGNUM */
extern NFast_BignumUpcalls sbn_upcalls;

/* Bignum utility functions ----------------------------- */

/** Convert a hex string to a bignum
 *
 * \return Status code
 */
extern int sbn_char2bignum ( struct NFast_Bignum **ppBN_out,
			const char *text,
			struct NFast_Application *app,
                        struct NFast_Call_Context *cctx,
                        struct NFast_Transaction_Context *tctx );

/** Convert a bignum to a hex string
 *
 * \return Status code
 */
extern int sbn_bignum2char ( char *buf, int buflen,
			const struct NFast_Bignum *pBN,
			struct NFast_Application *app,
                        struct NFast_Call_Context *cctx,
                        struct NFast_Transaction_Context *tctx );

/** Print a bignum in hex to a file
 *
 * Call ferror() to test for output errors.
 */
extern void sbn_printbignum ( FILE *f, 
		const char *prefix, const struct NFast_Bignum *pBN );


/** Compare two bignums
 *
 * \return -1, 0 or 1 if A\<B, A=B or A\>B
 */
extern int sbn_compare ( const struct NFast_Bignum *pA, 
			const struct NFast_Bignum *pB );

#ifdef __cplusplus
}
#endif

#endif

