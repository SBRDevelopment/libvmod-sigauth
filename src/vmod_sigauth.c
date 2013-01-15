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
vmod_sigstring(struct sess *sp, const char *name)
{
  char *p;
  unsigned u, v;

  //char *host = VRT_GetHdr(sp, HDR_REQ, "\030Host:");
  //char *date = VRT_GetHdr(sp, HDR_REQ, "\030Date:");

  u = WS_Reserve(sp->wrk->ws, 0); /* Reserve some work space */
  p = sp->wrk->ws->f;  /* Front of workspace area */
  v = snprintf(p, u, "%s %s", "2013-01-15T00:00:00", "api.sbrfeeds.com");
  v++;

  if (v > u) {
  /* No space, reset and leave */
    WS_Release(sp->wrk->ws, 0);
    return (NULL);
  }

  /* Update work space with what we've used */
  WS_Release(sp->wrk->ws, v);
  return (p);
}
