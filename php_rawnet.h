/***************************************************************************
 * File: php_rawnet.h                                   Part of php-rawnet *
 *                                                                         *
 * Copyright (C) 2019 Erik Lundin. All Rights Reserved.                    *
 *                                                                         *
 * This program is free software; you can redistribute it and/or modify    *
 * it under the terms of the GNU General Public License as published by    *
 * the Free Software Foundation; either version 2 of the License, or       *
 * (at your option) any later version.                                     *
 *                                                                         *
 * This program is distributed in the hope that it will be useful,         *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of          *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           *
 * GNU General Public License for more details.                            *
 *                                                                         *
 * You should have received a copy of the GNU General Public License       *
 * along with php-rawnet.  If not, see <http://www.gnu.org/licenses/>.     *
 *                                                                         *
 ***************************************************************************/

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#ifndef PHP_RAWNET_H
# define PHP_RAWNET_H

extern zend_module_entry rawnet_module_entry;
# define phpext_rawnet_ptr &rawnet_module_entry

# define PHP_RAWNET_VERSION "0.2.0"

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

