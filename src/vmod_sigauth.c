#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>

/*
 * mhash.h has a habit of pulling in assert(). Let's hope it's a define,
 * and that we can undef it, since Varnish has a better one.
 */
#include <mhash.h>
#ifdef assert
#	undef assert
#endif

#include "vrt.h"
#include "bin/varnishd/cache.h"

#include "vcc_if.h"
#include "config.h"

int
init_function(struct vmod_priv *priv, const struct VCL_conf *conf)
{
	return (0);
}

const char *
hmac_sha1(struct sess *sp, const char *key, const char *msg)
{
	MHASH td;
	hashid hash = MHASH_SHA1;
	size_t maclen = mhash_get_hash_pblock(hash);
	size_t blocksize = mhash_get_block_size(hash);
	unsigned char mac[blocksize];
	unsigned char *data;

	td = mhash_hmac_init(hash, (void *)key, strlen(key), mhash_get_hash_pblock(hash));
	mhash(td, msg, strlen(msg));
	mhash_hmac_deinit(td,mac);

	data = WS_Alloc(sp->ws, blocksize+1); // '\0'
	if (data == NULL)
		return NULL;

	for (int j = 0; j < blocksize; j++) {
		data[j] = (unsigned char)mac[j];
	}
	data[blocksize+1] = '\0';

	return data;
}

long
append_header_name(struct sess *sp, const struct http *hp, char *p, unsigned u) {

	unsigned l;
	char *c;
	txt hdr;

	assert(hp);
	Tcheck(hp->hd[u]);

	hdr = hp->hd[u];

	if (hdr.b == NULL)
		return 0;

	for(c = hdr.b; c < hdr.e; c++) {
		if(c[0] == ':') {
			l = c - hdr.b;
			break;
		}
	}

	assert(hdr.b[l] == ':');

	return sprintf(p, "%.*s", l, hdr.b);
}

const char *
get_headers(struct sess *sp, const struct http *hp) {

	int u, v;
	unsigned i;
	char *p;

	u = WS_Reserve(sp->wrk->ws, 0);
	p = sp->wrk->ws->f;

	for (i = HTTP_HDR_FIRST; i < hp->nhd; i++) {
		v += append_header_name(sp, hp, p, i);
	}
	v++;

	if(v > u) {
		// No space, release memory and leave
		WS_Release(sp->wrk->ws, 0);
		return (NULL);
	}

	// Release unused memory
	WS_Release(sp->wrk->ws, v);
	return (p);
}

const char *
vmod_sigstring(struct sess *sp,

		const char *secret
){
	const char *p;

	p = get_headers(sp, sp->http);

	return (p);
	//return hmac_sha1(sp, secret, buf);
}
