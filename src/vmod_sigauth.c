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
	int j;

	td = mhash_hmac_init(hash, (void *)key, strlen(key), mhash_get_hash_pblock(hash));
	mhash(td, msg, strlen(msg));
	mhash_hmac_deinit(td,mac);

	data = WS_Alloc(sp->ws, blocksize+1); // '\0'
	if (data == NULL)
		return NULL;

	for (j = 0; j < blocksize; j++) {
		data[j] = (unsigned char)mac[j];
	}
	data[blocksize+1] = '\0';

	return data;
}

const char *
vmod_sigstring(struct sess *sp,
		const char *method,
		const char *url,
		const char *date,
		const char *host,
		const char *body,
		const char *secret
){
	int len = 10;
	const char *digest;
	char *buf;

	len += strlen(method);
	len += strlen(url);

	if(date) len += strlen(date);
	if(host) len += strlen(host);

	buf = calloc(1, len + 1);

	strcat(buf, method);
	strcat(buf, "\n");

	strcat(buf, url);
	strcat(buf, "\n");

	if(date) strcat(buf, date);
	strcat(buf, "\n");

	if(host) strcat(buf, host);
	strcat(buf, "\n");

	if(body) strcat(buf, body);
	strcat(buf, "\n");


	return hmac_sha1(sp, secret, buf);
}
