/*
 * Copyright (c) 2016, Federico G. Schwindt <fgsch@lodoss.net>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <openssl/crypto.h>
#include <openssl/md4.h>
#include <openssl/md5.h>
#include <openssl/ripemd.h>
#include <openssl/sha.h>
#include <openssl/whrlpool.h>

#include "cache/cache.h"

#include "vrt.h"

#include "vcc_if.h"

#define SHA1_CBLOCK			SHA_CBLOCK
#define SHA1_CTX			SHA_CTX
#define SHA1_DIGEST_LENGTH		SHA_DIGEST_LENGTH
#define SHA224_CBLOCK			SHA256_CBLOCK
#define SHA224_CTX			SHA256_CTX
#define SHA384_CBLOCK			SHA512_CBLOCK
#define SHA384_CTX			SHA512_CTX
#define WHIRLPOOL_CBLOCK		0

#define CBLOCK_MAX			128
#define DIGEST_LENGTH_MAX		64


typedef int init_f(void *);
typedef int update_f(void *, const void *, unsigned long);
typedef int final_f(unsigned char *, void *);

struct vmod_crypto_hashspec {
	const char	*name;
	int		 cblock;
	int		 digest_length;
	init_f		*init;
	update_f	*update;
	final_f		*final;
};


static char *
hash_common(VRT_CTX, const struct vmod_crypto_hashspec *h, void *c,
    VCL_STRING s)
{
	unsigned char m[DIGEST_LENGTH_MAX];
	char *p;
	int i;

	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	if (!s) {
		VSLb(ctx->vsl, SLT_Error,
		    "crypto.hash_%s: No input", h->name);
		return (NULL);
	}
	p = WS_Alloc(ctx->ws, h->digest_length * 2 + 1);
	if (!p) {
		VSLb(ctx->vsl, SLT_Error,
		    "crypto.hash_%s: Out of workspace", h->name);
		return (NULL);
	}
	h->init(c);
	h->update(c, s, strlen(s));
	h->final(m, c);
	for (i = 0; i < h->digest_length; i++)
		sprintf(&p[i * 2], "%02x", m[i]);
	return (p);
}

static char *
hmac_common(VRT_CTX, const struct vmod_crypto_hashspec *h, void *c,
    VCL_STRING key, VCL_STRING message)
{
	unsigned char i_pad[CBLOCK_MAX], o_pad[CBLOCK_MAX];
	unsigned char m[DIGEST_LENGTH_MAX];
	int i, key_len;
	char *p;

	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	if (!key || !message) {
		VSLb(ctx->vsl, SLT_Error,
		    "crypto.hmac_%s: Missing %s", h->name,
		    !key ? "key" : "message");
		return (NULL);
	}
	p = WS_Alloc(ctx->ws, h->digest_length * 2 + 3);
	if (!p) {
		VSLb(ctx->vsl, SLT_Error,
		    "crypto.hmac_%s: Out of workspace", h->name);
		return (NULL);
	}
	key_len = strlen(key);
	/* Hash the key if it is longer than the block size. */
	if (key_len > h->cblock) {
		h->init(c);
		h->update(c, key, key_len);
		h->final(m, c);
		key = (const char *)m;
		key_len = h->digest_length;
	}
	memset(i_pad, 0, sizeof(i_pad));
	memset(o_pad, 0, sizeof(o_pad));
	memcpy(i_pad, key, key_len);
	memcpy(o_pad, key, key_len);
	/* XOR key with inner and outer padding constants. */
	for (i = 0; i < h->cblock; i++) {
		i_pad[i] ^= 0x36;
		o_pad[i] ^= 0x5c;
	}
	/* Inner hash. */
	h->init(c);
	h->update(c, i_pad, h->cblock);
	h->update(c, message, strlen(message));
	h->final(m, c);
	/* Outer hash. */
	h->init(c);
	h->update(c, o_pad, h->cblock);
	h->update(c, m, h->digest_length);
	h->final(m, c);
	sprintf(p, "0x");
	for (i = 0; i < h->digest_length; i++)
		sprintf(&p[i * 2 + 2], "%02x", m[i]);
	return (p);
}

#define VMOD_CRYPTO_HASHSPEC						\
H(md4, MD4)								\
H(md5, MD5)								\
H(ripemd160, RIPEMD160)							\
H(sha1, SHA1)								\
H(sha224, SHA224)							\
H(sha256, SHA256)							\
H(sha384, SHA384)							\
H(sha512, SHA512)							\
H(whirlpool, WHIRLPOOL)

#define H(n,p) 								\
h_##n,
enum {
VMOD_CRYPTO_HASHSPEC
};
#undef H

#define H(n,p) 								\
{ #n, p##_CBLOCK, p##_DIGEST_LENGTH,					\
  (init_f *)p##_Init, (update_f *)p##_Update, (final_f *)p##_Final },
const struct vmod_crypto_hashspec vmod_crypto_hashspec[] = {
VMOD_CRYPTO_HASHSPEC
};
#undef H

#define H(n,p)								\
VCL_STRING __match_proto__(td_crypto_hash_##n)				\
vmod_hash_##n(VRT_CTX, VCL_STRING s)					\
{									\
	p##_CTX c;							\
	return (hash_common(ctx, &vmod_crypto_hashspec[h_##n], &c, s));	\
}
VMOD_CRYPTO_HASHSPEC
#undef H

#undef VMOD_CRYPTO_HASHSPEC
#define VMOD_CRYPTO_HASHSPEC						\
H(md5, MD5)								\
H(sha1, SHA1)								\
H(sha224, SHA224)							\
H(sha256, SHA256)							\
H(sha384, SHA384)							\
H(sha512, SHA512)

#define H(n,p)								\
VCL_STRING __match_proto__(td_crypto_hmac_##n)				\
vmod_hmac_##n(VRT_CTX, VCL_STRING key, VCL_STRING message)		\
{									\
	p##_CTX c;							\
	return (hmac_common(ctx, &vmod_crypto_hashspec[h_##n], &c, key, \
	    message));							\
}
VMOD_CRYPTO_HASHSPEC
#undef H
