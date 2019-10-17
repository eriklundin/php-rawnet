/***************************************************************************
 * File: php_rawnet.h                                   Part of php-rawnet *
 *                                                                         *
 * Copyright (C) 2019 Erik Lundin.                                         *
 *                                                                         *
 * Permission is hereby granted, free of charge, to any person obtaining   *
 * a copy of this software and associated documentation files (the         *
 * "Software"), to deal in the Software without restriction, including     *
 * without limitation the rights to use, copy, modify, merge, publish,     *
 * distribute, sublicense, and/or sell copies of the Software, and to      *
 * permit persons to whom the Software is furnished to do so, subject to   *
 * the following conditions:                                               *
 *                                                                         *
 * The above copyright notice and this permission notice shall be          *
 * included in all copies or substantial portions of the Software.         *
 *                                                                         *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,         *
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF      *
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND                   *
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE  *
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION  *
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION   *
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.         *
 *                                                                         *
 ***************************************************************************/

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#ifndef PHP_RAWNET_H
# define PHP_RAWNET_H

extern zend_module_entry rawnet_module_entry;
# define phpext_rawnet_ptr &rawnet_module_entry

# define PHP_RAWNET_VERSION "0.2.1"

#define CAAL(s, v) add_assoc_long_ex(return_value, s, sizeof(s) - 1, (zend_long) v);
#define CAAS(s, v) add_assoc_string_ex(return_value, s, sizeof(s) - 1, (char *) (v ? v : ""));

#define PHP_SAFE_MAX_FD(m, n)	 do { if (m >= FD_SETSIZE) { _php_emit_fd_setsize_warning(m); m = FD_SETSIZE - 1; }} while(0)
#define PHP_SAFE_FD_SET(fd, set) do { if (fd < FD_SETSIZE) FD_SET(fd, set); } while(0)
#define PHP_SAFE_FD_ISSET(fd, set)  ((fd < FD_SETSIZE) && FD_ISSET(fd, set))

extern int le_rawnet;
#define le_rawnet_name "rawnet handle"

typedef struct {

	zend_resource	*res;
	int		socket;
	char		hostname[HOST_NAME_MAX];
	int		port;
	int		blocking;
	int		connecting;

	// SSL-properties
	SSL			*ssl;
	SSL_CTX			*ctx;
	char			*peer_cert;
	char			*peer_cert_cn;
	char			*peer_cert_serial;
	char			*peer_cert_fingerprint;

} php_rawnet;


# if defined(ZTS) && defined(COMPILE_DL_RAWNET)
ZEND_TSRMLS_CACHE_EXTERN()
# endif

#endif	/* PHP_RAWNET_H */

