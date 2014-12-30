 /* 
   * We will likely use:
   * 
   * int PEM_write_PKCS8PrivateKey(FILE *fp, EVP_PKEY *x, const EVP_CIPHER *enc,
   *                               char *kstr, int klen,
   *                               pem_password_cb *cb, void *u);
   *
   * fp is a file pointer to write the PEM file to.
   * x is a pointer to the private key structure.  Does this support all 
   *   requisite key types (RSA, DSA, EC)?
   * enc is a cipher to encrypt the key file: leave that NULL as we're
   *   not encrypting the fake key.  
   * kstr and klen are a buffer for the passphrase: NULL and 0 respectively
   * cb is a callback for the password prompt: NULL
   * u is another passphrase alternative: NULL. 
   */

  /* 
   * EVP_PKEY is a generic private key type created with EVP_PKEY_new(3).  
   * 
   * One can assign the actual key represented by an EVP_PKEY with the
   * routines: 
   * 
   * int EVP_PKEY_assign_RSA(EVP_PKEY *pkey,RSA *key);
   * int EVP_PKEY_assign_DSA(EVP_PKEY *pkey,DSA *key);
   * int EVP_PKEY_assign_DH(EVP_PKEY *pkey,DH *key);
   * int EVP_PKEY_assign_EC_KEY(EVP_PKEY *pkey,EC_KEY *key);
   * 
   * The RSA(3) case is a pointer to a struct defined as: 
   * 
   * struct
   *           {
   *           BIGNUM *n;              // public modulus
   *           BIGNUM *e;              // public exponent
   *           BIGNUM *d;              // private exponent
   *           BIGNUM *p;              // secret prime factor
   *           BIGNUM *q;              // secret prime factor
   *           BIGNUM *dmp1;           // d mod (p-1)
   *           BIGNUM *dmq1;           // d mod (q-1)
   *           BIGNUM *iqmp;           // q^-1 mod p
   *           // ...
   *           };
   *    RSA
   * 
   * So the tactic for the RSA case is to create this struct and set
   * the appropriate values, substituting a tag based on the NFKM Hash
   * of the key for the private exponent.
   *
   * For DSA(3) keys the struct is similar: 
   *
   * struct
   *           {
   *           BIGNUM *p;              // prime number (public)
   *           BIGNUM *q;              // 160-bit subprime, q | p-1 (public)
   *           BIGNUM *g;              // generator of subgroup (public)
   *           BIGNUM *priv_key;       // private key x
   *           BIGNUM *pub_key;        // public key y = g^x
   *           // ...
   *           }
   *     DSA;
   * 
   * The tag will be in the priv_key member.
   *
   * The struct pointed to by EC_KEY appears to be opaque (no
   * documented definition in the installed header files) so we'll
   * have to use functions to set the appropriate parameters.  This
   * may make things more complicated as these functions might check
   * consistency etc. which is not necessarily something we want.
   *
   * Looks like the docs for ECC keys did not make it into the CentOS
   * package, but they are here: 
   * https://www.openssl.org/docs/crypto/ec.html
   *
   * Create the new key structure with: EC_KEY *EC_KEY_new(void);
   * What is the least amount of information we can get away with?
   * Set the private key with: 
   *   int EC_KEY_set_private_key(EC_KEY *key, const BIGNUM *prv);
   * Set the public key with:
   *   int EC_KEY_set_public_key(EC_KEY *key, const EC_POINT *pub);
   * How to make an EC_POINT? 
   *   EC_POINT *EC_POINT_new(const EC_GROUP *group);
   * And then use:
   *   EC_POINT *EC_POINT_bn2point(const EC_GROUP *, const BIGNUM *,
   *      EC_POINT *, BN_CTX *);
   * 
   * Need to supply the EC_GROUP for this, which is the actual Curve
   * definition.  The key itself may need to know this too.  But this
   * function BETTER NOT TRANSFORM ANYTHING as the values obtained out
   * of the HSM are already a valid point on that curve.  
   * 
   * Probably do them in this order as RSA and DSA are much less
   * complicated and we can use that to shake out our BIGNUM
   * implementation.  Then tackle the ECC stuff.
   *
   */