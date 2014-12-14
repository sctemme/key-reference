/*
*   NFUTIL.H
*
*   General-purpose NFast utility functions header
*
* Copyright 1996-1999 nCipher Corporation Limited.
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

#ifndef NFUTIL_H
#define NFUTIL_H

#include "nfastapp.h"

#ifdef __cplusplus
extern "C" {
#endif

/* 'Duplicate' functions ----------------------------------------------

	These make a copy of a piece of memory,	using whatever memory
	allocation functions are set for the given 'app'
*/
	
extern void *nfutil_dup ( const void *psrc, size_t len, 
		NFast_AppHandle app,
		struct NFast_Call_Context *cctx,
		struct NFast_Transaction_Context *tctx);

/* Allocates a block of memory length 'len', and then copies
	data from 'psrc' (if it's non-NULL), or sets it to zero (if
	it is NULL). Returns a pointer to the memory, or NULL if
	no memory */


#define nfutil_duphash(h,app,cctx,tctx) \
	((M_Hash *)nfutil_dup((h),sizeof(M_Hash),(app),(cctx),(tctx)))


extern int nfutil_dupbyteblock ( M_ByteBlock *dst,
		const M_ByteBlock *src,
		NFast_AppHandle app,
		struct NFast_Call_Context *cctx,
		struct NFast_Transaction_Context *tctx);

/* Duplicates a 'ByteBlock' structure: allocates a block the
	same length as the 'src' byteblock, copies the data, and
	sets 'dst' fields to point to it. Return Status_OK for
	success or NOMEM otherwise */


/* ACL management functions -------------------------------

   These allow an ACL to be built up piece-by-piece.

*/

extern void nfutil_InitACL ( M_ACL *pACL,
		NFast_AppHandle app,
		struct NFast_Call_Context *cctx,
		struct NFast_Transaction_Context *tctx);

/* Initialises an M_ACL structure, ready for calling subsequent functions */

extern M_PermissionGroup *nfutil_AddPG ( M_ACL *pACL,
		const M_Hash *certifier,
		NFast_AppHandle app,
		struct NFast_Call_Context *cctx,
		struct NFast_Transaction_Context *tctx);

/* Adds a Permission Group to an ACL structure. Returns a pointer to
	the PermissionGroup (ready for use with nfutil_Addxxx functions)
	or NULL if no memory. If 'certifier' is non-NULL, it is used as
	the key hash used to sign certificates for this group */

extern M_Action *nfutil_AddAction (
		M_PermissionGroup *pPG,
		NFast_AppHandle app,
		struct NFast_Call_Context *cctx,
		struct NFast_Transaction_Context *tctx );

/* Adds an Action Entry to a permission group & returns a pointer, or
	NULL if no memory. This entry is set to all zeroes, so should
	be initialised before use */

extern M_UseLimit *nfutil_AddUseLimit (
		M_PermissionGroup *pPG,
		NFast_AppHandle app,
		struct NFast_Call_Context *cctx,
		struct NFast_Transaction_Context *tctx );

/* Adds a Use Limit to a permission group & returns a pointer, or
	NULL if no memory. As with nfutil_AddAction, this needs
	initialising before use */

extern M_Action *nfutil_AddOpPermissions (
		M_PermissionGroup *pPG,
		M_Word perms,
		NFast_AppHandle app,
		struct NFast_Call_Context *cctx,
		struct NFast_Transaction_Context *tctx );

/* Calls nfutil_AddAction to add an action entry, then initialises it
	as an OpPermissions type entry with the permissions given by
	'perms'. Returns a pointer, or NULL if no memory */

extern M_Action *nfutil_AddMakeBlob (
		M_PermissionGroup *pPG,
		M_Word flags,
		const M_Hash *pHKM,
		const M_Hash *pHKT,
		const M_TokenParams *pTP,
		NFast_AppHandle app,
		struct NFast_Call_Context *cctx,
		struct NFast_Transaction_Context *tctx );

/* Calls nfutil_AddAction to add an action entry, then initialises it
	as a MakeBlob type entry with the fields given by 'flags',
	'pHKM', 'pHKT' and 'pTP'. Any or all of these last 3 may be NULL
	pointers. Returns a pointer, or NULL if no memory */

extern M_Action *nfutil_AddMakeArchiveBlob (
		M_PermissionGroup *pPG,
		M_Word flags,
		M_Mech mech,
		const M_Hash *pHKA,
		NFast_AppHandle app,
		struct NFast_Call_Context *cctx,
		struct NFast_Transaction_Context *tctx );

/* Calls nfutil_AddAction to add an action entry, then initialises it
	as a MakeArchiveBlob type entry with the given 'flags' and 'mech'
	fields. If pHKA is non-NULL, this is set as the 'ka' archive key
	hash */

extern int nfutil_MakeSimpleACL ( M_ACL *pACL,
		M_Word oppermissions,
		NFast_AppHandle app,
		struct NFast_Call_Context *cctx,
		struct NFast_Transaction_Context *tctx);

/* Creates a simple ACL in one go. Calls nfutil_InitACL(), then
	nfutil_AddPG() to add a permission group, then
	nfutil_AddOpPermissions() to add an OpPermissions action entry */

/* Miscellaneous functions -------------------------------

*/

void nfutil_copybytes ( unsigned char *dst, const unsigned char *src,
	unsigned nbytes, int swapends, int swapwords );

/* Copies bytes from src to dst, possibly swapping the order of bytes
	within 32-bit words (if 'swapends' is true) and/or the order of
	words within the block (if 'swapwords' is true). nbytes *must*
	be a multiple of 4 i.e. a whole number of M_Words.
*/


extern void assert_rc(const char *msg, int rc);
/* If rc != Status_OK, does an NFast_Perror with the
   given msg and rc, then calls exit(1) */

void assert_rc_ei(const char *msg, M_Status rc,
		  const union M_Status__ErrorInfo *ei);
/* Like assert_rc, only prints the errorinfo from the command
 * too.  You should use this function for printing errors
 * from commands. */

#ifdef __cplusplus
}
#endif

#endif
