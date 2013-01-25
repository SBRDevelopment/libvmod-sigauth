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

#define HASH MHASH_SHA1
#define MACLEN mhash_get_hash_pblock(HASH)
#define BLOCKSIZE mhash_get_block_size(HASH)
#define HEADER_PREFIX_SIZE 32

char *header_prefix;
const char *base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                           "abcdefghijklmnopqrstuvwxyz"
                           "0123456789+/";

int
init_function(struct vmod_priv *priv, const struct VCL_conf *conf)
{
	header_prefix = calloc(HEADER_PREFIX_SIZE, 1);
	memcpy(header_prefix, "x-auth", 7);
	return (0);
}

int
hdrsize(const struct http *hp) {
	CHECK_OBJ_NOTNULL(hp, HTTP_MAGIC);
	return hp->nhd - HTTP_HDR_FIRST;
}

char *
hdrtolower(char *h) {
	int i;
	for(i = 0; i < strlen(h); i++) {
		*(h+i) = tolower(*(h+i));
	}
	return h;
}

int
hdrcompare (const void *a, const void *b)
{
    /* Offset the headers to ignore the first length byte and compare the names */
    return strcasecmp (*(const char **)a + 1, *(const char **)b + 1);
}

const char *
base64_encode(struct sess *sp, const unsigned char *in, size_t inlen) {

	unsigned outlenorig, outlen;
	unsigned char tmp[3], idx;
	char *out, *outb;

	AN(in);
	CHECK_OBJ_NOTNULL(sp, SESS_MAGIC);

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
hmac_sha1(struct sess *sp, const char *key, const char *msg)
{
	MHASH td;
	unsigned char *data, mac[BLOCKSIZE];

	AN(key);
	CHECK_OBJ_NOTNULL(sp, SESS_MAGIC);

	td = mhash_hmac_init(HASH, (void *)key, strlen(key), MACLEN);
	mhash(td, msg, strlen(msg));
	mhash_hmac_deinit(td,mac);

	data = WS_Alloc(sp->ws, BLOCKSIZE);
	if (data == NULL)
		return NULL;

	for (int j = 0; j < BLOCKSIZE; j++) {
		data[j] = (unsigned char)mac[j];
	}

	return data;
}

char *
get_header_name(struct sess *sp, const struct http *hp, unsigned u) {

	char *c, *p;
	int i;
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
	for(c = hdr.b, i = 0; c < hdr.e; c++, i++) {
		if(c[0] == ':') {
			p = WS_Alloc(sp->ws, i + 3); 		/* Allocate memory ( l + \0xx + ':' ) */
			sprintf(p, "%c%.*s:", i + 1, i, hdr.b);
			return p;
		}
	}

	return NULL;
}

char *
get_headers(struct sess *sp, const struct http *hp) {

	int HEADER_SIZE = hdrsize(hp);
	char *hdrl[HEADER_SIZE], *p, *pptr;
	int j, i;

	CHECK_OBJ_NOTNULL(sp, SESS_MAGIC);
	CHECK_OBJ_NOTNULL(hp, HTTP_MAGIC);

	for (i = HTTP_HDR_FIRST, j = 0; i < hp->nhd; i++, j++) {
		hdrl[j] = hdrtolower(get_header_name(sp, hp, i));
	}

	// Sort the headers case insensitive
	qsort(hdrl, HEADER_SIZE, sizeof(const char *), hdrcompare);

	unsigned r = WS_Reserve(sp->wrk->ws, 0);
	p = pptr = sp->wrk->ws->f;

	for (i = 0; i < HEADER_SIZE; i++) {
		syslog(LOG_INFO, "%s %s\n", hdrl[i], VRT_GetHdr(sp, HDR_REQ, hdrl[i]));
		if (strcasecmp(hdrl[i], "\005date:") == 0 ||
			strcasecmp(hdrl[i], "\005host:") == 0 ||
			strncasecmp(hdrl[i]+1, header_prefix, strlen(header_prefix)) == 0) {
			pptr += sprintf(pptr, "%s %s\n", hdrl[i] + 1 /* skip length prefix */, VRT_GetHdr(sp, HDR_REQ, hdrl[i]));
		}
	}

	/* Out of memory, run away!! */
	if ((pptr - p) > r) {
		WS_Release(sp->wrk->ws, 0);
		return NULL;
	}

	WS_Release(sp->wrk->ws, (pptr - p));

	return p;
}

int
get_body(struct sess *sp, char**body, unsigned long *ocl) {

	int re, buf_size, rsize;
	char *cl_ptr, buf[2048];
	unsigned long cl;

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

void
vmod_init(struct sess *sp, struct vmod_priv *priv, const char *prefix) {

	assert(prefix);
	assert(strlen(prefix) < HEADER_PREFIX_SIZE);

	memset(header_prefix, 0, HEADER_PREFIX_SIZE);
	sprintf(header_prefix, "%s", prefix);
}

const char *
vmod_signature(struct sess *sp, const char *method, const char *uri, const char *secret){

	char *b, *body;
	int i[3];
	unsigned long cl;

	const char *h = get_headers(sp, sp->http);
	int ret = get_body(sp, &body, &cl);

	if ( ret != 1 ) cl = 0;

	i[0] = strlen(method);
	i[1] = i[0] + strlen(uri);
	i[2] = i[1] + strlen(h);

	int l = i[0] + i[1] + i[2] + cl + 3;

	b = WS_Alloc(sp->wrk->ws, l);
	
	syslog(LOG_INFO, "vmod_signature| %d, %d, %d, %d", i[0], i[1], i[2], cl);
	syslog(LOG_INFO, "vmod_signature| length %d", l);

	memcpy(b, method, i[0]);
	memcpy(b + i[0], "\n", 1);
	memcpy(b + 1 + i[0], uri, i[1]);
	memcpy(b + 1 + i[1], "\n", 1);
	memcpy(b + 2 + i[1], h, i[2]);
	
	syslog(LOG_INFO, "%s", b);

	if(ret == 1) {
		memcpy(b + 2 + i[2], body, cl);
	}

	memcpy(b + 2 + i[2] + cl, "\0", 1);

	char *d = hmac_sha1(sp, secret, b);

	syslog(LOG_INFO, "vmod_signature| (%d) %s", l, b);

	return base64_encode(sp, d, BLOCKSIZE);
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
