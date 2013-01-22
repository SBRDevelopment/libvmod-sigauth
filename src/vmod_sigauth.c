#include <stdlib.h>
#include <stdarg.h>
#include <syslog.h>
#include <stdio.h>
#include <time.h>

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


const char *base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                           "abcdefghijklmnopqrstuvwxyz"
                           "0123456789+/";

int
init_function(struct vmod_priv *priv, const struct VCL_conf *conf)
{
	return (0);
}

int
sizeofhdr(const struct http *hp) {
	CHECK_OBJ_NOTNULL(hp, HTTP_MAGIC);
	return hp->nhd - HTTP_HDR_FIRST;
}


char *
tolowerhdr(char *h) {
	int i;
	for(i = 0; i < strlen(h); i++) {
		*(h+i) = tolower(*(h+i));
	}
	return h;
}

int
comparehdr (const void *a, const void *b)
{
    /* Offset the headers to ignore the first length byte and compare the names */
    return strcasecmp (*(const char **) a + 1, *(const char **) b + 1);
}

const char *
base64_encode(struct sess *sp, const unsigned char *in, size_t inlen) {

	unsigned outlenorig, outlen;
	char *out, *outb;
	unsigned char tmp[3], idx;

	CHECK_OBJ_NOTNULL(sp, SESS_MAGIC);
	AN(in);

	outlen = outlenorig = WS_Reserve(sp->wrk->ws, 0);
	outb = out = sp->wrk->ws->f;

	if (outlen < 4) {
		WS_Release(sp->wrk->ws, 0);
		return NULL;
	}

	if (inlen == 0) {
		*out = '\0';
		WS_Release(sp->wrk->ws, 1);
		return outb;
	}

	while (1) {

		assert(inlen);
		assert(outlen>3);
		tmp[0] = (unsigned char) in[0];
		tmp[1] = (unsigned char) in[1];
		tmp[2] = (unsigned char) in[2];


		*out++ = base64_chars[(tmp[0] >> 2) & 0x3f];

		idx = (tmp[0] << 4);
		if (inlen>1)
			idx += (tmp[1] >> 4);
		idx &= 0x3f;
		*out++ = base64_chars[idx];

		if (inlen>1) {
			idx = (tmp[1] << 2);
			if (inlen>2)
				idx += tmp[2] >> 6;
			idx &= 0x3f;

			*out++ = base64_chars[idx];
		} else {
			*out++ = '=';
		}

		if (inlen>2) {
			*out++ = base64_chars[tmp[2] & 0x3f];
		} else {
			*out++ = '=';
		}

		if (outlen<5) {
			WS_Release(sp->wrk->ws, 0);
			return NULL;
		}
		outlen -= 4;

		if (inlen<4)
			break;

		inlen -= 3;
		in += 3;
	}
	assert(outlen);

	outlen--;
	*out = '\0';

	WS_Release(sp->wrk->ws, outlenorig-outlen);

	return outb;
}

unsigned char *
hmac_sha1(struct sess *sp, const char *key, const char *msg, int *outlen)
{
	MHASH td;
	hashid hash = MHASH_SHA1;
	size_t maclen = mhash_get_hash_pblock(hash);
	size_t blocksize = mhash_get_block_size(hash);
	unsigned char mac[blocksize];
	unsigned char *data;

	AN(key);
	CHECK_OBJ_NOTNULL(sp, SESS_MAGIC);

	td = mhash_hmac_init(hash, (void *)key, strlen(key), mhash_get_hash_pblock(hash));
	mhash(td, msg, strlen(msg));
	mhash_hmac_deinit(td,mac);

	data = WS_Alloc(sp->ws, blocksize);
	if (data == NULL)
		return NULL;

	for (int j = 0; j < blocksize; j++) {
		data[j] = (unsigned char)mac[j];
	}

	*outlen = blocksize;
	return data;
}

char *
get_header_name(struct sess *sp, const struct http *hp, unsigned u) {

	char *c, *p;
	size_t l;
	txt hdr;

	CHECK_OBJ_NOTNULL(sp, SESS_MAGIC);
	CHECK_OBJ_NOTNULL(hp, HTTP_MAGIC);
	Tcheck(hp->hd[u]);

	hdr = hp->hd[u];

	if (hdr.b == NULL)
		return 0;

	// The ':' character indicates the end of the header name
	// so loop through each character in the string and then
	// add the header name to the buffer.
	for(c = hdr.b, l = 0; c < hdr.e; c++, l++) {
		if(c[0] == ':') {
			p = WS_Alloc(sp->ws, l + 3); 		/* Allocate memory ( l + \0xx + ':' ) */
			sprintf(p, "%c%.*s:", l + 1, l, hdr.b);
			return p;
		}
	}

	return NULL;
}

const char *
get_headers(struct sess *sp, const struct http *hp) {

	unsigned u, r, l, j, i;
	unsigned h = sizeofhdr(hp);
	const char *hdrl[h];
	const char *p;
	const char *pptr;

	CHECK_OBJ_NOTNULL(sp, SESS_MAGIC);
	CHECK_OBJ_NOTNULL(hp, HTTP_MAGIC);

	for (l = HTTP_HDR_FIRST, j = 0; l < hp->nhd; l++, j++) {
		hdrl[j] = tolowerhdr(get_header_name(sp, hp, l));
	}

	qsort (hdrl, h, sizeof(const char *), comparehdr);

	// Should be faster to just allocate all the memory and
	// release it when done instead of trying to calculate how much
	// we need to reserve.
	r = WS_Reserve(sp->wrk->ws, 0);
	p = pptr = sp->wrk->ws->f;

	for (i = 0; i < h; i++) {
		if (strcasecmp(hdrl[i], "\005date:") == 0 ||
			strcasecmp(hdrl[i], "\005host:") == 0 ||
			strncasecmp(hdrl[i]+1, "x-sbr", 5) == 0) {
			pptr += sprintf(pptr, "%s %s\n", hdrl[i] + 1 /* skip length prefix */, VRT_GetHdr(sp, HDR_REQ, hdrl[i]));
		}
	}

	u = pptr - p;

	/* Out of memory, run away!! */
	if (u > r) {
		WS_Release(sp->wrk->ws, 0);
		return NULL;
	}

	WS_Release(sp->wrk->ws, u);

	return p;
}

int
get_body(struct sess *sp, char**body, int *ocl) {

	char *cl_ptr;
	unsigned long cl;
	int re, buf_size, rsize;
	char buf[2048];

	CHECK_OBJ_NOTNULL(sp, SESS_MAGIC);

	cl_ptr = VRT_GetHdr(sp, HDR_REQ, "\017Content-Length:");
	if (!cl_ptr) return -2;

	*ocl = cl = strtoul(cl_ptr, NULL, 10);
	if (cl <= 0) return -2;

	if(sp->htc->pipeline.b != NULL && Tlen(sp->htc->pipeline) == cl) {
		*body = sp->htc->pipeline.b;
	} else {
		int rxbuf_size = Tlen(sp->htc->rxbuf);

		// Do ws work
		int u = WS_Reserve(sp->wrk->ws, 0);
		if( u < cl + rxbuf_size + 1) {
			WS_Release(sp->wrk->ws, 0);
			return -3;
		}
		*body = (char*)sp->wrk->ws->f;
		memcpy(*body, sp->htc->rxbuf.b, rxbuf_size);
		sp->htc->rxbuf.b = *body;
		*body += rxbuf_size;
		*body[0] = 0;
		sp->htc->rxbuf.e = *body;
		WS_Release(sp->wrk->ws, cl + rxbuf_size + 1);

		// Read post data
		re = 0;
		while(cl) {
			if(cl > sizeof(buf)) {
				buf_size = sizeof(buf) - 1;
			} else {
				buf_size = cl;
			}

			rsize = HTC_Read(sp->wrk, sp->htc, buf, buf_size);
			if (rsize <= 0) {
				return -3;
			}

			cl -= rsize;

			memcpy(*body + re, buf, buf_size);
			re += rsize;
		}

		sp->htc->pipeline.b = *body;
		sp->htc->pipeline.e = *body + *ocl;
	}
	return 1;
}

const char *
vmod_signature(struct sess *sp, const char *method, const char *uri, const char *secret){

	int cl, l;
	char *b;
	char *body;

	const char *h = get_headers(sp, sp->http);
	int ret = get_body(sp, &body, &cl);

	int u = WS_Reserve(sp->wrk->ws, 0);
	b = sp->wrk->ws->f;

	if(ret == 1) {
		l = sprintf(b, "%s\n%s\n%s%s", method, uri, h, body);
	} else {
		l = sprintf(b, "%s\n%s\n%s", method, uri, h);
	}

	if (l > u) {
		WS_Release(sp->wrk->ws, 0);
		return NULL;
	}

	WS_Release(sp->wrk->ws, l);

	int dlen;
	char *d = hmac_sha1(sp, secret, b, &dlen);

	return base64_encode(sp, d, dlen);
}

int
vmod_isexpired(struct sess *sp, const char *expiration) {

	long e;
	time_t t;

	AN(expiration);

	e = atol(expiration);
	time(&t);

	return (long)t >= e;
}
