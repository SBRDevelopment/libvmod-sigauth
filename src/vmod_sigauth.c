#include <stdlib.h>

#include "vrt.h"
#include "bin/varnishd/cache.h"

#include "vcc_if.h"

int
init_function(struct vmod_priv *priv, const struct VCL_conf *conf)
{
	return (0);
}

const char *
vmod_sigstring(struct sess *sp, const char *name,...)
{
	va_list ap;
	char *p;

	va_start(ap, name);
	p = VRT_String(sp->wrk->ws, NULL, name, ap);
	va_end(ap);

	return (p);
}
