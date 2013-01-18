#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <syslog.h>

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

int
sizeofhdr(const struct http *hp) {
	CHECK_OBJ_NOTNULL(hp, HTTP_MAGIC);
	return hp->nhd - HTTP_HDR_FIRST;
}

int
comparehdr (const void * a, const void * b)
{
    /* Offset the headers to ignore the first length byte and compare the names */
    return strcasecmp (*(const char **) a + 1, *(const char **) b + 1);
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

	AN(key);
	CHECK_OBJ_NOTNULL(sp, SESS_MAGIC);

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
			//syslog(LOG_INFO, "get_header_name| header %c%.*s:", l + 1, l, hdr.b);
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
		hdrl[j] = get_header_name(sp, hp, l);
	}

	qsort (hdrl, h, sizeof(const char *), comparehdr);

	// Should be faster to just allocate all the memory and
	// release it when done instead of trying to calculate how much
	// we need to reserve.
	r = WS_Reserve(sp->wrk->ws, 0);
	p = sp->wrk->ws->f;
	pptr = p;

	for (i = 0; i < h; i++) {
		if (strcasecmp(hdrl[i], "\005date:") == 0 ||
			strcasecmp(hdrl[i], "\005host:") == 0 ||
			strncasecmp(hdrl[i]+1, "x-sbr", 5) == 0) {
			pptr += sprintf(pptr, "%s %s\n", hdrl[i] + 1 /* skip length prefix */, VRT_GetHdr(sp, HDR_REQ, hdrl[i]));
			//syslog(LOG_INFO, "get_headers| header %d: %s = %s\n", i, hdrl[i], VRT_GetHdr(sp, HDR_REQ, hdrl[i]));
		}
	}

	pptr++;
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

	//syslog(LOG_INFO, "get_body| pipeline length %d", Tlen(sp->htc->pipeline));
	if(sp->htc->pipeline.b != NULL && Tlen(sp->htc->pipeline) == cl) {
		//syslog(LOG_INFO, "get_body| complete buffer %s", sp->htc->pipeline.b);
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

			//syslog(LOG_INFO, "get_body| reading %u bytes into buffer", buf_size);
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

		//syslog(LOG_INFO, "get_body| complete buffer %s", *body);
	}
	return 1;
}

const char *
vmod_sigstring(struct sess *sp, const char *method, const char *uri, const char *secret){

	int cl;
	char *body;

	int ret = get_body(sp, &body, &cl);
	const char *h = get_headers(sp, sp->http);

	int len = strlen(method) + 1 + strlen(uri) + 1 + strlen(h) + strlen(body);
	char *o = WS_Alloc(sp->ws, len);

	strcat(o, method);
	strcat(o, "\n");
	strcat(o, uri);
	strcat(o, "\n");
	strcat(o, h);
	strcat(o, body);

	const char *d = hmac_sha1(sp, secret, o);

	//syslog(LOG_INFO, "vmod_sigstring| method %s", method);
	//syslog(LOG_INFO, "vmod_sigstring| uri %s", uri);
	//syslog(LOG_INFO, "vmod_sigstring| headers %s", h);
	//syslog(LOG_INFO, "vmod_sigstring| body %s", body);

	//syslog(LOG_INFO, "bmod_sigstring| string_to_sign %s", o);

	//syslog(LOG_INFO, "vmod_sigstring| hmac-sha1 %s", d);

	return (d);
}
