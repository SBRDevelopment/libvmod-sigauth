============
vmod_sigauth
============

----------------------
Varnish Sigauth Module
----------------------

:Author: Brian Wight
:Date: 2013-01-15
:Version: 1.0
:Manual section: 3

SYNOPSIS
========

import sigauth;

DESCRIPTION
===========

Authorizes a signed request passed to varnish.  

FUNCTIONS
=========

signature
---------

Prototype
        ::

                signature(STRING METHOD, STRING URI, STRING SECRET_KEY)
Return value
	STRING
Description
	Returns 	base64(hmac_sha1(canonicalized_request_data))
Example
        ::

                set req.http.signature = sigauth.signature(req.request, req.url, "izY8UUW9rvumTICDWERMOvtrzlc4m2T0/QkSRHVY");

isexpired
---------

Prototype
		::
		
				isexpired(STRING EXPIRATION)
Return value
	STRING
Description
	Returns		NOW <= EXPIRATION
Example
				if(req.url ~ "^.*Expires=([\d^&]+)(.*)+$") {
					if(sigauth.isexpired(regsub(req.url, ".*Expires=([\d]+)", "\1")) == 1) {
						return (error);
					}
				}

INSTALLATION
============

The source tree is based on autotools to configure the building, and
does also have the necessary bits in place to do functional unit tests
using the varnishtest tool.

Usage::

 ./configure VARNISHSRC=DIR [VMODDIR=DIR]

`VARNISHSRC` is the directory of the Varnish source tree for which to
compile your vmod. Both the `VARNISHSRC` and `VARNISHSRC/include`
will be added to the include search paths for your module.

Optionally you can also set the vmod install directory by adding
`VMODDIR=DIR` (defaults to the pkg-config discovered directory from your
Varnish installation).

Make targets:

* make - builds the vmod
* make install - installs your vmod in `VMODDIR`
* make check - runs the unit tests in ``src/tests/*.vtc``

In your VCL you could then use this vmod along the following lines::
        
        import sigauth;

        sub vcl_recv {
                # This sets req.http.signature to a base64 encoded signature
                set req.http.signature = sigauth.signature(req.request, req.url, "izY8UUW9rvumTICDWERMOvtrzlc4m2T0/QkSRHVY");
        }

HISTORY
=======

This manual page was released as part of the libvmod-sigauth package.

COPYRIGHT
=========

This document is licensed under the same license as the
libvmod-sigauth project. See LICENSE for details.

* Copyright (c) 2013 Brian Wight
