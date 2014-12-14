/*
*   SIMPLEBIGNUM.C
*
*   Simple bignumber upcalls
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
*   Copyright 2001 - 2002 nCipher Corporation Limited.
*/

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>

#include "nfastapp.h"
#include "nfutil.h"
#include "simplebignum.h"

/* --------------------- */

int sbn_bignumreceiveupcall(struct NFast_Application *app,
                               struct NFast_Call_Context *cctx,
                               struct NFast_Transaction_Context *tctx,
                               M_Bignum *bignum, int nbytes,
                               const void *source,
                               int msbitfirst, int mswordfirst)
{
  struct NFast_Bignum *pBN;

  if ( nbytes > MAXBIGNUMBITS/8 ) return Status_OutOfRange;
  assert( (nbytes & 3)==0 );

  pBN = (struct NFast_Bignum *)NFastApp_Malloc(app, sizeof(struct NFast_Bignum), cctx, tctx);
  if ( !pBN ) return NOMEM;

  nfutil_copybytes(pBN->bytes, (const unsigned char *)source,
	nbytes, 0, 0);

  pBN->msb_first = msbitfirst;
  pBN->msw_first = mswordfirst;
  pBN->nbytes=nbytes;
  *bignum=pBN;
  return Status_OK;
}

/* --------------------- */

int sbn_bignumsendlenupcall(struct NFast_Application *app,
                               struct NFast_Call_Context *cctx,
                               struct NFast_Transaction_Context *tctx,
                               const M_Bignum *bignum, int *nbytes_r)
{
  assert( ((*bignum)->nbytes & 3)==0 );
  *nbytes_r= (*bignum)->nbytes;
  return Status_OK;
}

/* --------------------- */

int sbn_bignumsendupcall(struct NFast_Application *app,
                            struct NFast_Call_Context *cctx,
                            struct NFast_Transaction_Context *tctx,
                            const M_Bignum *bignum, int nbytes,
                            void *dest, int msbitfirst, int mswordfirst)
{
  int swapends, swapwords;
  struct NFast_Bignum *pBN = *bignum;

  assert( pBN->nbytes==nbytes );

  /* Is format which we're sending in the same as that of the
     bignumber? 
     (NB '!' used to constrain result to 0,1 range)
     If not, work out which ends to swap.
  */

  swapends = (!msbitfirst) ^ (!pBN->msb_first);
  swapwords = (!mswordfirst) ^ (!pBN->msw_first);
  nfutil_copybytes( (unsigned char *)dest, (*bignum)->bytes, nbytes,
	swapends, swapwords );
  return Status_OK;
}

/* --------------------- */

void sbn_bignumfreeupcall(struct NFast_Application *app,
                             struct NFast_Call_Context *cctx,
                             struct NFast_Transaction_Context *tctx,
                             M_Bignum *bignum)
{
  NFastApp_Free(app, (*bignum), cctx, tctx);
  *bignum=NULL;
}

/* --------------------- */

int sbn_bignumformatupcall(struct NFast_Application *app,
                              struct NFast_Call_Context *cctx,
                              struct NFast_Transaction_Context *tctx,
                              int *msbitfirst_io, int *mswordfirst_io)
{
  /* Send to the module in little-endian format.
     (This is not officially necessary. However, some
     versions of the monitor (Maintenance mode) don't accept
     big-endian bignums due to a bug) */
  *msbitfirst_io=0;
  *mswordfirst_io=0;
  return Status_OK;
}

NFast_BignumUpcalls sbn_upcalls = {
  sbn_bignumreceiveupcall,
  sbn_bignumsendlenupcall,
  sbn_bignumsendupcall,
  sbn_bignumfreeupcall,
  sbn_bignumformatupcall
};

/* --------------------- */

static int char2hex ( char c )
{
  if ( c >= '0' && c <= '9' ) return c-'0';
  if ( c >= 'A' && c <= 'F' ) return c-'A'+10;
  if ( c >= 'a' && c <= 'f' ) return c-'a'+10;
  return -1;
}

/* --------------------- */

int sbn_char2bignum ( struct NFast_Bignum **ppBN_out,
			const char *text,
			struct NFast_Application *app,
                        struct NFast_Call_Context *cctx,
                        struct NFast_Transaction_Context *tctx )
{
  struct NFast_Bignum *pBN;
  int d;
  size_t len, i;

  /* Strip leading whitespace */

  while ( text[0] != 0 && isspace((unsigned char)text[0]) )
    text++;

  /* Strip trailing whitespace */
  len=strlen(text);
  while ( len > 0 && isspace((unsigned char)text[len-1]) )
    len--;

  if ( len > MAXBIGNUMBITS/4 ) return Status_OutOfRange;

  pBN = (struct NFast_Bignum *)NFastApp_Malloc(app, sizeof(struct NFast_Bignum), cctx, tctx);
  if ( !pBN ) return NOMEM;

  pBN->msb_first = 0;
  pBN->msw_first = 0;

  /* Read in from the LS digit */
  for ( i=0; i<len; i++ )
  {
    d = char2hex(text[len-1-i]);
    if ( d < 0 ) return Status_Malformed;
    if ( i & 1 )
      pBN->bytes[i/2] |= (d << 4);
    else
      pBN->bytes[i/2] = d;
  }

  /* Pad to words if necessary */
  i = (len+1)/2;
  while ( (i & 3) != 0 )
    pBN->bytes[i++] = 0;

  assert(i <= INT_MAX);
  pBN->nbytes=(int)i;
  *ppBN_out=pBN;
  return Status_OK;
}

/* --------------------- */

static int getbyte ( const struct NFast_Bignum *pN, int pos )
{
  /* Get a byte from a bignum, taking account of possible strange endianness */
  if ( pos >= pN->nbytes ) return 0;

  if ( pN->msb_first ) pos ^= 3; /* Big endian words */

  if ( pN->msw_first )
  {
    pos = pN->nbytes-1-pos;
    pos ^= 3;
  }

  return pN->bytes[pos];
}

/* --------------------- */

static int getbytelen ( const struct NFast_Bignum *pN )
{
  int n=pN->nbytes-1;
  while ( n >= 0 && getbyte(pN, n)==0 )
    n--;

  return n+1;
}

/* --------------------- */

int sbn_bignum2char ( char *buf, int buflen,
			const struct NFast_Bignum *pBN,
			struct NFast_Application *app,
                        struct NFast_Call_Context *cctx,
                        struct NFast_Transaction_Context *tctx )
{
  int i, d, pos, len;
  static const char *hexdigits="0123456789ABCDEF";

  len = pBN->nbytes;

  pos = len*2+1;
  if ( buflen < pos )
    return Status_BufferFull;

  buf[--pos] = 0;

  for ( i=0; i<len; i++ )
  {
    d = getbyte(pBN,i);
    buf[--pos] = hexdigits[d & 0xF];
    buf[--pos] = hexdigits[(d>>4) & 0xF];
  }

  return Status_OK;
}

/* --------------------- */

void sbn_printbignum ( FILE *f, const char *prefix, const struct NFast_Bignum *pBN )
{
  char buf[MAXBIGNUMBITS/4+1];
  int rc;

  rc=sbn_bignum2char(buf, sizeof(buf), pBN, NULL, NULL, NULL);
  if ( rc != Status_OK ) strcpy(buf, "<invalid length>");
  fprintf( f, "%s=\n %s\n", prefix, buf );
}

/* --------------------- */

int sbn_compare ( const struct NFast_Bignum *pA, 
			const struct NFast_Bignum *pB )
{
  int i, aa, bb;

  aa=getbytelen(pA); 
  bb=getbytelen(pB);
  if ( aa != bb ) return (aa > bb) ? 1 : -1;

  i=aa;
  while ( i-- > 0 )
  {
    aa=getbyte(pA,i);
    bb=getbyte(pB,i);
    if ( aa != bb ) return (aa > bb) ? 1 : -1;
  }

  return 0;
}


