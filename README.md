libvmod-crypto
==============

[![Join the chat at https://gitter.im/fgsch/libvmod-crypto](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/fgsch/libvmod-crypto?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)
[![Build Status](https://travis-ci.org/fgsch/libvmod-crypto.svg?branch=master)](https://travis-ci.org/fgsch/libvmod-crypto)

## About

A Varnish 4 and 5 VMOD to compute message digests and keyed-hash message
authentication codes (HMAC).

## Requirements

To build this VMOD you will need:

* make
* a C compiler, e.g. GCC or clang
* pkg-config
* python-docutils
* libvarnishapi-dev in Debian/Ubuntu or varnish-libs-devel in CentOS/RedHat
* libssl-dev in Debian/Ubuntu or openssl-devel in CentOS/RedHat

If you are building from Git, you will also need:

* autoconf
* automake
* libtool

In addition, to run the tests you will need:

* varnish

If varnish is installed in a non-standard prefix you will also need
to set `PKG_CONFIG_PATH` to the directory where **varnishapi.pc** is
located before running `autogen.sh` and `configure`.  For example:

```
export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
```

## Installation

### From a tarball

To install this VMOD, run the following commands:

```
./configure
make
make check
sudo make install
```

The `make check` step is optional but it's good to know whether the
tests are passing on your platform.

### From the Git repository

To install from Git, clone this repository by running:

```
git clone https://github.com/fgsch/libvmod-crypto
```

And then run `./autogen.sh` followed by the instructions above for
installing from a tarball.

## Example

```
import crypto;

sub vcl_recv {
	if (crypto.hmac_sha256("secret",
	    req.http.host + req.url + req.http.timestamp) != req.http.hmac) {
		return (synth(401));
	}
}
```

## License

This VMOD is licensed under BSD license. See LICENSE for details.
