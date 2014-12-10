# Copyright (C) 2014 Thales e-Security, Inc.  All rights reserved.
# This example source code is provided for your information and assistance.
# Note that there is NO WARRANTY.

# Sample ident only good in my Security World
# appname pkcs11
# ident   uada174c9f8c05edceeac194a19c3c57a529bb1cf2

import nfpython as nf
import nfkm
import sys

def extract_keydata(appname, ident):
    conn = nf.connection()
    swinfo=nfkm.getinfo(conn)

    keyinfo = nfkm.findkey(conn, appname, ident)

    # Get first usable module from Security World info
    for m in swinfo.modules:
        if m.state == 'Usable':
            break

    module = m.module

    # The module variable now has the first usable module
    # Load the public half of the key onto it

    r = conn.transact(nf.Command(['LoadBlob', 0, 0, module, keyinfo.pubblob]))

    if r.status != 'OK': 
        exit(1)

    pubkey = r.reply.idka

    r = conn.transact(nf.Command(['GetKeyInfoEx', 0, 0, pubkey]))
    keytype = r.reply.type
    keylength = r.reply.length
    nfkmhash = r.reply.hash

    r = conn.transact(nf.Command(['Export', 0, pubkey]))
    pubkeydata = r.reply.data.data
    
    return {'type': keytype, 'length': keylength, 'hash': nfkmhash, 'pubkey': pubkeydata }

if __name__ == "__main__":
    appname = sys.argv[1]
    ident   = sys.argv[2]
    keydata = extract_keydata(appname, ident)
    
    print keydata