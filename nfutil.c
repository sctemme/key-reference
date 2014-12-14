/*
*   NFUTIL.C
*
*   General-purpose NFast utility functions
*
*   These can be used in any nFast application; no private
*	definitions are involved.
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
* Copyright 1999 nCipher Corporation Limited.
*/

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "nfastapp.h"
#include "nfutil.h"

/* --------------------- */

void assert_rc(const char *msg, int rc)
{
  if ( rc != Status_OK )
  {
    NFast_Perror(msg,rc);
    exit(1);
  }
}

/* --------------------- */

void assert_rc_ei(const char *msg, M_Status rc,
		  const union M_Status__ErrorInfo *ei)
{
  char buf[100];
  
  if ( rc == Status_OK ) return;
  NFast_StrError(buf,sizeof(buf), rc,ei);
  fprintf(stderr,"%s: %s\n",msg,buf);
  exit(1);
}

/* --------------------- */

void *nfutil_dup ( const void *psrc, size_t len, 
		NFast_AppHandle app,
		struct NFast_Call_Context *cctx,
		struct NFast_Transaction_Context *tctx)
{
  void *p;

  if ( len==0 ) len=1;	/* Else might get NULL malloc result */

  p = NFastApp_Malloc(app, len, cctx, tctx );
  if ( p==NULL ) return NULL;

  if ( psrc != NULL )
    memcpy(p,psrc,len);
  else
    memset(p, 0, len);

  return p;
}

/* --------------------- */

int nfutil_dupbyteblock ( M_ByteBlock *dst,
		const M_ByteBlock *src,
		NFast_AppHandle app,
		struct NFast_Call_Context *cctx,
		struct NFast_Transaction_Context *tctx)
{
  assert(dst != NULL);
  assert(src != NULL);

  dst->ptr = nfutil_dup(src->ptr, src->len, app, cctx, tctx);
  if ( dst->ptr==NULL ) return NOMEM;
  dst->len = src->len;
  return Status_OK;
}

/* --------------------- */

void nfutil_copybytes ( unsigned char *dst, const unsigned char *src,
	unsigned nbytes, int swapends, int swapwords )
{
  int inc;
  unsigned nwords;

  /* Copies dst to src, swapping endianness and/or word order. dst and src mustn't overlap! */

  assert( (nbytes & 3)==0 ); /* Must be whole number of M_Words */

  if ( !swapends && !swapwords )
  {
    memcpy(dst, src, nbytes);
    return;
  }

  if ( swapwords )
  {
    dst += (nbytes-4);
    inc=-4;
  }
  else
    inc=4;

  nwords = nbytes>>2;

  if ( swapends )
  {
    while ( nwords-- > 0 )
    {
      dst[0]=src[3];
      dst[1]=src[2];
      dst[2]=src[1];
      dst[3]=src[0];
      dst += inc;
      src += 4;
    }
  }
  else
  {
    while ( nwords-- > 0 )
    {
      dst[0]=src[0];
      dst[1]=src[1];
      dst[2]=src[2];
      dst[3]=src[3];
      dst += inc;
      src += 4;
    }
  }
}

/* ACL functions ---------------------------------------- */

void nfutil_InitACL ( M_ACL *pACL,
		NFast_AppHandle app,
		struct NFast_Call_Context *cctx,
		struct NFast_Transaction_Context *tctx)
{
  assert(pACL != NULL);
  
  memset(pACL, 0, sizeof(M_ACL));
}

/* --------------------- */

M_PermissionGroup *nfutil_AddPG ( M_ACL *pACL,
		const M_Hash *certifier,
		NFast_AppHandle app,
		struct NFast_Call_Context *cctx,
		struct NFast_Transaction_Context *tctx)
{
  M_PermissionGroup *pPG;

  /* Add extra permission group to table, realloc'ing if necessary */
  assert(pACL != NULL);

  if ( pACL->groups==NULL )
  {
    assert(pACL->n_groups==0);
    pPG=(M_PermissionGroup *) NFastApp_Malloc(app,
		sizeof(M_PermissionGroup), cctx, tctx);
  }
  else
  {
    pPG=(M_PermissionGroup *) NFastApp_Realloc(app, pACL->groups,
		(1+pACL->n_groups)*sizeof(M_PermissionGroup),
		cctx, tctx);
  }

  if ( !pPG ) return NULL; /* No memory */
  pACL->groups=pPG;	   /* New larger table */

  /* Now fill it in */

  pPG=&pACL->groups[pACL->n_groups];
  memset(pPG, 0, sizeof(M_PermissionGroup));

  if ( certifier )
  {
    pPG->flags |= PermissionGroup_flags_certifier_present;
    pPG->certifier = nfutil_duphash(certifier, app, cctx, tctx);
    if ( !pPG->certifier ) return NULL;
	/* No memory, return without adding extra group */
  }

  pACL->n_groups++;
  return pPG;
}

/* --------------------- */

M_Action *nfutil_AddAction (
		M_PermissionGroup *pPG,
		NFast_AppHandle app,
		struct NFast_Call_Context *cctx,
		struct NFast_Transaction_Context *tctx )
{
  /* Adds action entry to a permission group */
  M_Action *pAE;

  assert(pPG != NULL);
  
  if ( pPG->actions==NULL )
  {
    assert(pPG->n_actions==0);
    pAE=(M_Action *) NFastApp_Malloc(app,
		sizeof(M_Action), cctx, tctx);
  }
  else
  {
    pAE=(M_Action *) NFastApp_Realloc(app, pPG->actions,
		(1+pPG->n_actions)*sizeof(M_Action),
		cctx, tctx);
  }

  if ( !pAE ) return NULL; /* No memory */
  pPG->actions=pAE;	   /* New larger table */

  pAE += pPG->n_actions;
  pPG->n_actions++;
  memset(pAE, 0, sizeof(M_Action));
  return pAE;
}

/* --------------------- */

M_UseLimit *nfutil_AddUseLimit (
		M_PermissionGroup *pPG,
		NFast_AppHandle app,
		struct NFast_Call_Context *cctx,
		struct NFast_Transaction_Context *tctx )
{
  /* Adds action entry to a permission group */
  M_UseLimit *pUL;

  assert(pPG != NULL);
  
  if ( pPG->limits==NULL )
  {
    assert(pPG->n_limits==0);
    pUL=(M_UseLimit *) NFastApp_Malloc(app,
		sizeof(M_UseLimit), cctx, tctx);
  }
  else
  {
    pUL=(M_UseLimit *) NFastApp_Realloc(app, pPG->limits,
		(1+pPG->n_limits)*sizeof(M_UseLimit),
		cctx, tctx);
  }

  if ( !pUL ) return NULL; /* No memory */
  pPG->limits=pUL;	   /* New larger table */

  pUL += pPG->n_limits;
  pPG->n_limits++;
  memset(pUL, 0, sizeof(M_UseLimit));
  return pUL;
}

/* --------------------- */

M_Action *nfutil_AddOpPermissions (
		M_PermissionGroup *pPG,
		M_Word perms,
		NFast_AppHandle app,
		struct NFast_Call_Context *cctx,
		struct NFast_Transaction_Context *tctx )
{
  M_Action *pAE;

  pAE = nfutil_AddAction(pPG, app, cctx, tctx);
  if ( !pAE ) return NULL;

  pAE->type = Act_OpPermissions;
  pAE->details.oppermissions.perms = perms;
  return pAE;
}

/* --------------------- */

M_Action *nfutil_AddMakeBlob (
		M_PermissionGroup *pPG,
		M_Word flags,
		const M_Hash *pHKM,
		const M_Hash *pHKT,
		const M_TokenParams *pTP,
		NFast_AppHandle app,
		struct NFast_Call_Context *cctx,
		struct NFast_Transaction_Context *tctx )
{
  M_Action *pAE;

  pAE = nfutil_AddAction(pPG, app, cctx, tctx);
  if ( !pAE ) return NULL;

  pAE->type = Act_MakeBlob;
  pAE->details.makeblob.flags = flags;

  if ( pHKM != NULL )
  {
    pAE->details.makeblob.flags |= Act_MakeBlob_Details_flags_kmhash_present;
    pAE->details.makeblob.kmhash = nfutil_duphash(pHKM, app, cctx, tctx);
    if ( pAE->details.makeblob.kmhash==NULL ) goto no_memory;
  }

  if ( pHKT != NULL )
  {
    pAE->details.makeblob.flags |= Act_MakeBlob_Details_flags_kthash_present;
    pAE->details.makeblob.kthash = nfutil_duphash(pHKT, app, cctx, tctx);
    if ( pAE->details.makeblob.kthash==NULL ) goto no_memory;
  }

  if ( pTP != NULL )
  {
    pAE->details.makeblob.flags |= Act_MakeBlob_Details_flags_ktparams_present;
    pAE->details.makeblob.ktparams = (M_TokenParams *)nfutil_dup(pTP,
		sizeof(M_TokenParams), app, cctx, tctx);
    if ( pAE->details.makeblob.ktparams==NULL ) goto no_memory;
  }

  return pAE;

no_memory:
  NFastApp_Free(app, pAE->details.makeblob.kmhash, cctx, tctx);
  NFastApp_Free(app, pAE->details.makeblob.kthash, cctx, tctx);
  NFastApp_Free(app, pAE->details.makeblob.ktparams, cctx, tctx);
  memset(pAE, 0, sizeof(M_Action));
  pPG->n_actions--;
  return NULL;
}

/* --------------------- */

M_Action *nfutil_AddMakeArchiveBlob (
		M_PermissionGroup *pPG,
		M_Word flags,
		M_Mech mech,
		const M_Hash *pHKA,
		NFast_AppHandle app,
		struct NFast_Call_Context *cctx,
		struct NFast_Transaction_Context *tctx )
{
  M_Action *pAE;

  pAE = nfutil_AddAction(pPG, app, cctx, tctx);
  if ( !pAE ) return NULL;

  pAE->type = Act_MakeArchiveBlob;
  pAE->details.makearchiveblob.flags = flags;
  pAE->details.makearchiveblob.mech = mech;

  if ( pHKA != NULL )
  {
    pAE->details.makearchiveblob.flags |= Act_MakeArchiveBlob_Details_flags_kahash_present;
    pAE->details.makearchiveblob.kahash = nfutil_duphash(pHKA, app, cctx, tctx);
    if ( pAE->details.makearchiveblob.kahash==NULL ) goto no_memory;
  }

  return pAE;

no_memory:
  NFastApp_Free(app, pAE->details.makearchiveblob.kahash, cctx, tctx);
  memset(pAE, 0, sizeof(M_Action));
  pPG->n_actions--;
  return NULL;
}

/* --------------------- */

int nfutil_MakeSimpleACL ( M_ACL *pACL,
		M_Word oppermissions,
		NFast_AppHandle app,
		struct NFast_Call_Context *cctx,
		struct NFast_Transaction_Context *tctx)
{
  M_PermissionGroup *pPG;

  nfutil_InitACL(pACL, app, cctx, tctx);

  pPG = nfutil_AddPG(pACL, NULL, app, cctx, tctx );
  if (pPG==NULL) return NOMEM;

  if ( nfutil_AddOpPermissions(pPG, oppermissions, app, cctx, tctx) == NULL )
    return NOMEM;

  return Status_OK;
}

