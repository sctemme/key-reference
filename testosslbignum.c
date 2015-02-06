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

#include <strings.h>
#include <string.h>

#include "osslbignum.h"

/* 16 bytes "Big"nums with msbitfirst, patterned to readily show which
   order the bytes end up in */
#define BIGEND { 0x44, 0x43, 0x42, 0x41, 0x34, 0x33, 0x32, 0x31, 0x24, 0x23, 0x22, 0x21, 0x14, 0x13, 0x12, 0x11 }
#define LTLEND { 0x11, 0x12, 0x13, 0x14, 0x21, 0x22, 0x23, 0x24, 0x31, 0x32, 0x33, 0x34, 0x41, 0x42, 0x43, 0x44 }

/* Hex  msbitfirst  !msbitfirst
 * 0x01 0001        1000 0x08
 * 0x02 0010        0100 0x04
 * 0x03 0011        1100 0x0C
 * 0x04 0100        0010 0x02
 */

/* Same with my above interpretation of least significant bit first */
#define BIGENDLSB { 0x22, 0x2C, 0x24, 0x28, 0xC2, 0xCC, 0xC4, 0xC8, 0x42, 0x4C, 0x44, 0x48, 0x82, 0x8C, 0x84, 0x88 }
#define LTLENDLSB { 0x88 0x84, 0x8C, 0x82, 0x48, 0x44, 0x4C, 0x42, 0xC8, 0xC4, 0xCC, 0xC2, 0x28, 0x24, 0x2C, 0x22 }

#define BUGOUT(rc, text) if ((rc)) {                    \
    NFast_Perror((text), (rc));                         \
    goto cleanup;                                       \
  }

int main (int argc, char *argv[])
{
  M_Bignum bignum = NULL;
  int status, len;
  NFast_AppHandle nfapp;
  NFastAppInitArgs nfargs;
  const unsigned char bufbigend[] = BIGEND;
  const unsigned char bufltlend[] = LTLEND;
  unsigned char bufout[16];

  bzero(&nfargs, sizeof(nfargs));
  nfargs.flags = NFAPP_IF_BIGNUM;
  nfargs.bignumupcalls = &osslbn_upcalls;
  status = NFastApp_InitEx(&nfapp, &nfargs, NULL);
  BUGOUT(status, "Error initializing nCore");

  status = NFastApp_LoadBignum(nfapp, NULL, NULL, &bignum,
			       bufbigend, 16, 1, 1);
  BUGOUT(status, "Error loading BIGNUM");
  status = BN_bn2bin((const BIGNUM *)(bignum->bn), bufout);
  if (0 == memcmp(bufbigend, bufout, 16)) 
    printf("Load test succeeded: Big-endian garbage in.\n");
  else
    printf("Load test failed: Big-endian number did not load correctly.\n");

  status = NFastApp_GetBignumLen(nfapp, NULL, NULL, bignum, &len);
  BUGOUT(status, "Error getting BIGNUM length");
  if (len == 16)
    printf("Length correctly reported.\n");
  else
    printf("Length incorrectly reported: expected %d got %d.\n", 16, len);

  status = NFastApp_StoreBignum(nfapp, NULL, NULL, bignum, bufout, len, 1, 1);
  BUGOUT(status, "Error extracting BIGNUM in Big-Endian format");
  if (0 == memcmp(bufbigend, bufout, 16))
    printf("BIGNUM extraction in Bigendian format succeeded.\n");
  else
    printf("BIGNUM extraction in Bigendian format fialed.\n");
  status = NFastApp_StoreBignum(nfapp, NULL, NULL, bignum, bufout, len, 0, 0);
  if (0 == memcmp(bufltlend, bufout, 16))
    printf("BIGNUM extraction in Little-endian format succeeded.\n");
  else
    printf("BIGNUM extraction in Liggle-endian format failed.\n");

  NFastApp_FreeBignum(nfapp, NULL, NULL, &bignum);
  if (bignum == NULL)
    printf("Freeing BIGNUM succeeded!\n");
  else
    printf("Freeing BIGNUM failed.\n");
  
 cleanup: 
  return 0;
}
