#include <stdlib.h>
#include <string.h>

#include "vrt.h"
#include "bin/varnishd/cache.h"

#include "vcc_if.h"

int
init_function(struct vmod_priv *priv, const struct VCL_conf *conf)
{
	return (0);
}

const char *
vmod_sigstring(struct sess *sp,
		const char *method,
		const char *url,
		const char *date,
		const char *host
){
	int len = 4;
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

	return(buf);
}
