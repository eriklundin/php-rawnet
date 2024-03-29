/***************************************************************************
 * File: rawnet.c                                       Part of php-rawnet *
 *                                                                         *
 * Copyright (C) 2019-2021 Erik Lundin.                                    *
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "php.h"
#include "ext/standard/info.h"
#include "zend_interfaces.h"
#include "php_network.h"
#include "php_rawnet.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>

zend_class_entry *rawnet_ce;
static zend_object_handlers rawnet_object_handlers;

static zend_object *rawnet_create_object(zend_class_entry *class_type) {
	php_rawnet *intern = zend_object_alloc(sizeof(php_rawnet), class_type);
	zend_object_std_init(&intern->std, class_type);
	object_properties_init(&intern->std, class_type);
	intern->std.handlers = &rawnet_object_handlers;
	return &intern->std;
}

static zend_function *rawnet_get_constructor(zend_object *object) {
	zend_throw_error(NULL, "Cannot directly construct Rawnet, use rawnet_init() instead");
	return NULL;
}

static void rawnet_free_obj(zend_object *object) {
	php_rawnet *rawnet = rawnet_from_obj(object);
	zend_object_std_dtor(&rawnet->std);
}

static HashTable *rawnet_get_gc(zend_object *object, zval **table, int *n) {
	php_rawnet *rawnet = rawnet_from_obj(object);
	return zend_std_get_properties(object);
}

/* For compatibility with older PHP versions */
#ifndef ZEND_PARSE_PARAMETERS_NONE
#define ZEND_PARSE_PARAMETERS_NONE() \
	ZEND_PARSE_PARAMETERS_START(0, 0) \
	ZEND_PARSE_PARAMETERS_END()
#endif

static const char hexcodes[] = "0123456789ABCDEF";

void _rawnet_init_openssl() {
	SSL_load_error_strings();
	SSL_library_init();
	ERR_load_BIO_strings();
	OpenSSL_add_all_algorithms();
}

void _rawnet_get_cert_data(X509 *xs, php_rawnet *res) {

	BIO *bio = NULL;
	BUF_MEM *bio_buf = NULL;

	if ((bio = BIO_new(BIO_s_mem())) == NULL)
	        return;

	PEM_write_bio_X509(bio, xs);
	BIO_get_mem_ptr(bio, &bio_buf);
	res->peer_cert = NULL;
	res->peer_cert = ecalloc(1, bio_buf->length);
	snprintf(res->peer_cert, bio_buf->length, bio_buf->data);
	BIO_free(bio);
}

void _rawnet_get_cert_cn(X509 *xs, php_rawnet *res) {
	char peer_CN[256];
	int tmplen;
	X509_NAME_get_text_by_NID(X509_get_subject_name(xs), NID_commonName, peer_CN, 256);
	tmplen = strlen(peer_CN);
	res->peer_cert_cn = ecalloc(1, tmplen + 1);
	snprintf(res->peer_cert_cn, strlen(peer_CN) + 1, "%s", peer_CN);
}

void _rawnet_get_cert_serial(X509 *xs, php_rawnet *res) {
	BIO *bio;
	int n;
	if ((bio = BIO_new(BIO_s_mem())) == NULL)
		return;
	i2a_ASN1_INTEGER(bio, X509_get_serialNumber(xs));
	n = BIO_pending(bio);
	res->peer_cert_serial = ecalloc(1, n + 1);
	n = BIO_read(bio, res->peer_cert_serial, n);
	res->peer_cert_serial[n] = '\0';
	BIO_free(bio);
}

void _rawnet_get_cert_fingerprint(X509 *xs, php_rawnet *res) {

	unsigned int n;
	unsigned char md[255];
	int j;

	if(X509_digest(xs, EVP_sha1(), md, &n)) {
		res->peer_cert_fingerprint = ecalloc(1, 50);
		for(j = 0; j < (int) n; j++) {
			res->peer_cert_fingerprint[j * 2] = hexcodes[(md[j] & 0xf0) >> 4];
			res->peer_cert_fingerprint[(j * 2) + 1] = hexcodes[(md[j] & 0x0f)];
			if(j + 1 == (int) n) {
				res->peer_cert_fingerprint[(j * 2) + 2] = '\0';
			}
		}
	}
}


int _rawnet_nonblock(int s, int val) {
	int flags;
	flags = fcntl(s, F_GETFL, 0);

	if(val)
		flags |= O_NONBLOCK;
	else
		flags &= ~O_NONBLOCK;

	if(fcntl(s, F_SETFL, flags) < 0) {
		return -1;
	}
	return 1;
}


static int _rawnet_array_to_fd(uint32_t arg_num, zval *arr, fd_set *fds, int *max_fd) {

	zval *elem;
	php_rawnet *res;
	int c = 0;

	if(Z_TYPE_P(arr) != IS_ARRAY)
		return 0;

	ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(arr), elem) {

		ZVAL_DEREF(elem);

		if(Z_TYPE_P(elem) != IS_OBJECT || Z_OBJCE_P(elem) != rawnet_ce) {
			zend_argument_type_error(arg_num, "must only have elements of type Rawnet, %s given", zend_zval_type_name(elem));
			return 0;
		}

		res = Z_RAWNET_P(elem);

		if(res->socket < 0)
			continue;

		PHP_SAFE_FD_SET(res->socket, fds);
		if(res->socket > *max_fd) {
			*max_fd = res->socket;
		}
		c++;

	} ZEND_HASH_FOREACH_END();

	return c > 0 ? 1 : 0;
}

static int _rawnet_fd_to_array(uint32_t arg_num, zval *arr, fd_set *fds) {

	zval *elem, *dest_elem;
	HashTable *ht;
	php_rawnet *res;
	int ret = 0;
	zend_string *key;
	zend_ulong num_ind;

	if(Z_TYPE_P(arr) != IS_ARRAY)
		return 0;

	ht = zend_new_array(zend_hash_num_elements(Z_ARRVAL_P(arr)));
	ZEND_HASH_FOREACH_KEY_VAL(Z_ARRVAL_P(arr), num_ind, key, elem) {

		ZVAL_DEREF(elem);

		if(Z_TYPE_P(elem) != IS_OBJECT || Z_OBJCE_P(elem) != rawnet_ce) {
			zend_argument_type_error(arg_num, "must only have elements of type Rawnet, %s given", zend_zval_type_name(elem));
			return 0;
		}

		res = Z_RAWNET_P(elem);

		if(res->socket < 0)
			continue;

		if(!PHP_SAFE_FD_ISSET(res->socket, fds))
			continue;

		if (!key) {
			dest_elem = zend_hash_index_update(ht, num_ind, elem);
		} else {
			dest_elem = zend_hash_update(ht, key, elem);
		}

		zval_add_ref(dest_elem);
		ret++;

	} ZEND_HASH_FOREACH_END();

	// Destroy old array and add new one
	zval_ptr_dtor(arr);
	ZVAL_ARR(arr, ht);

	return ret;
}

/* {{{ resource rawnet_init()
 */
PHP_FUNCTION(rawnet_init) {

	php_rawnet *rn;

	ZEND_PARSE_PARAMETERS_NONE();

	object_init_ex(return_value, rawnet_ce);
	rn = Z_RAWNET_P(return_value);

	// Default blocking
	rn->blocking = 1;

	rn->ctx = NULL;
	rn->ssl = NULL;
	rn->peer_cert = NULL;
	rn->peer_cert_cn = NULL;
	rn->peer_cert_serial = NULL;
	rn->peer_cert_fingerprint = NULL;
	rn->connecting = 0;
	rn->ctx_init = 0;
}
/* }}} */

/* {{{ mixed rawnet_connect( resource $rn, string $hostname, int $port, [ int $timeout_sec = 3] )
 */
PHP_FUNCTION(rawnet_connect) {

	php_rawnet *res;
	zval *zid;
	zend_long port, timeout_sec = -1;
	zend_string *hostname;
	char errmsg[255];
	struct sockaddr_in addr;
	struct hostent *host;
	struct timeval tv;
	struct pollfd ufds;
	int i, len, ret;

	ZEND_PARSE_PARAMETERS_START(3,4)
		Z_PARAM_OBJECT_OF_CLASS(zid, rawnet_ce)
		Z_PARAM_STR(hostname)
		Z_PARAM_LONG(port)
		Z_PARAM_OPTIONAL
		Z_PARAM_LONG(timeout_sec)
	ZEND_PARSE_PARAMETERS_END();

	res = Z_RAWNET_P(zid);

	if(res->socket != -1 && res->connecting == 1) {

		len = sizeof(i);
		i = 0;
		ufds.fd = res->socket;
		ufds.events = POLLOUT;

		if(poll(&ufds, 1, 0) > 0) {
			ret = getsockopt(res->socket, SOL_SOCKET, SO_ERROR, &i, &len);
			if(ret < 0) {
				snprintf(errmsg, sizeof(errmsg), "Unable to connect to %s:%d (%d: %s)", res->hostname, res->port, errno, strerror(errno));
				goto cleanup;
			}

			if(i != 0) {
				snprintf(errmsg, sizeof(errmsg), "Unable to connect to %s:%d (%s)", res->hostname, res->port, strerror(i));
				goto cleanup;
			}

			res->connecting = 0;
			RETURN_TRUE;
		} else {
			RETURN_FALSE;
		}

	}

	// Resolve the hostname
	snprintf(res->hostname, sizeof(res->hostname), "%s", ZSTR_VAL(hostname));
	if((host = gethostbyname(res->hostname)) == NULL) {
			snprintf(errmsg, sizeof(errmsg), "Unable to resolve host: %s", res->hostname);
			RETURN_STRING(errmsg);
	}

	if((res->socket = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		snprintf(errmsg, sizeof(errmsg), "Unable to create socket (%d: %s)", errno, strerror(errno));
		res->socket = -1;
		RETURN_STRING(errmsg);
	}

	res->port = port;
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(res->port);
	addr.sin_addr.s_addr = *(long*)(host->h_addr);

	// Set timeout
	bzero(&tv, sizeof(tv));
	tv.tv_sec = (timeout_sec == -1 ? 3 : timeout_sec);

	if(setsockopt(res->socket, SOL_SOCKET, SO_RCVTIMEO, (struct timeval *)&tv, sizeof(tv)) < 0) {
		snprintf(errmsg, sizeof(errmsg), "Unable to set receive-timeout on socket (%d: %s)", errno, strerror(errno));
		goto cleanup;
	}

	if(setsockopt(res->socket, SOL_SOCKET, SO_SNDTIMEO, (struct timeval *)&tv, sizeof(tv)) < 0) {
		snprintf(errmsg, sizeof(errmsg), "Unable to set send-timeout on socket (%d: %s)", errno, strerror(errno));
		goto cleanup;
	}

	if(res->blocking == 0) {
		if(_rawnet_nonblock(res->socket, 1) < 0) {
			snprintf(errmsg, sizeof(errmsg), "Unable to set socket to none-blocking");
			goto cleanup;
		}
	}

	res->connecting = 1;
	if(connect(res->socket, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
		switch(errno) {
			case EAGAIN:
			case EINTR:
			case EINPROGRESS:
			case EALREADY:
				RETURN_FALSE;
			break;
			default:
				snprintf(errmsg, sizeof(errmsg), "Unable to connect to: %s:%d (%d: %s)", res->hostname, res->port, errno, strerror(errno));
				goto cleanup;
		}
	}

	RETURN_TRUE;

	cleanup:

	close(res->socket);
	res->connecting = 0;
	res->socket = -1;
	RETURN_STRING(errmsg);

}
/* }}}*/

/* {{{ mixed rawnet_read( resource $rn, int $length )
 */
PHP_FUNCTION(rawnet_read) {

	php_rawnet *res;
	zval *zid;
	zend_long rlen;
	zend_string *result;
	char *buf = NULL;
	int ssl_errcode, ret, readret;

	ZEND_PARSE_PARAMETERS_START(2,2)
		Z_PARAM_OBJECT_OF_CLASS(zid, rawnet_ce)
		Z_PARAM_LONG(rlen)
	ZEND_PARSE_PARAMETERS_END();

	res = Z_RAWNET_P(zid);

	buf = emalloc(rlen + 1);

	if(res->ssl == NULL) {
		readret = read(res->socket, buf, rlen);
		if(readret > 0) {

			result = zend_string_safe_alloc(readret, 1, 0, 0);
			memcpy(ZSTR_VAL(result), buf, readret);
			ZSTR_VAL(result)[readret] = '\0';

			efree(buf);
			RETURN_NEW_STR(result);

		} else if(readret == 0) {
			efree(buf);
			RETURN_FALSE;
		} else {
			efree(buf);
			if(errno == EAGAIN || errno == EWOULDBLOCK)
				RETURN_TRUE;

			// Disconnect
			RETURN_FALSE;
		}
	}


	// SSL
	ret = SSL_read(res->ssl, buf, rlen);
	ssl_errcode = SSL_get_error(res->ssl, 0);

	if(ret > 0) {

		// Success
		result = zend_string_safe_alloc(ret, 1, 0, 0);
		memcpy(ZSTR_VAL(result), buf, ret);
		ZSTR_VAL(result)[ret] = '\0';

		efree(buf);
		RETURN_NEW_STR(result);

	}

	efree(buf);
	switch(ssl_errcode) {
		case SSL_ERROR_WANT_READ:
		case SSL_ERROR_WANT_WRITE:
			RETURN_TRUE;
		case SSL_ERROR_SYSCALL:
			if (errno == EWOULDBLOCK || errno == EAGAIN) {
				RETURN_TRUE;
			}
			RETURN_FALSE;
		case SSL_ERROR_SSL:
			RETURN_FALSE;
		case SSL_ERROR_ZERO_RETURN:
			// Peer disconnected
			RETURN_FALSE;
		default:
			// Unknown error
			RETURN_FALSE;
	}
}
/* }}}*/


/* {{{ mixed rawnet_write( resource $rn, string $data )
 */
PHP_FUNCTION(rawnet_write) {

	php_rawnet *res;
	zval *zid;
	zend_string *wdata;
	int ssl_errcode, ret;

	ZEND_PARSE_PARAMETERS_START(2,2)
		Z_PARAM_OBJECT_OF_CLASS(zid, rawnet_ce)
		Z_PARAM_STR(wdata)
	ZEND_PARSE_PARAMETERS_END();

	res = Z_RAWNET_P(zid);

	if(res->ssl == NULL) {
		ret = write(res->socket, ZSTR_VAL(wdata), ZSTR_LEN(wdata));
		if(ret < 1) {
			RETURN_FALSE;
		}
		RETURN_LONG(ret);
	}

	// SSL
	ret = SSL_write(res->ssl, ZSTR_VAL(wdata), ZSTR_LEN(wdata));
	ssl_errcode = SSL_get_error(res->ssl, 0);

	if(ret > 0) {
		// Success
		RETURN_LONG(ret);
	}

	switch(ssl_errcode) {
		case SSL_ERROR_WANT_READ:
		case SSL_ERROR_WANT_WRITE:
			RETURN_TRUE;
		case SSL_ERROR_SYSCALL:
			if(errno == EWOULDBLOCK || errno == EAGAIN) {
				RETURN_TRUE;
			}
			RETURN_FALSE;
		default:
			// Unknown error
			RETURN_FALSE;
	}
}
/* }}}*/

/* {{{ mixed rawnet_select( array $a_read, array $a_write, array $a_except, int seconds, [ int microseconds ] )
 */
PHP_FUNCTION(rawnet_select) {

	zval *r_arr, *w_arr, *e_arr;
	fd_set rfds, wfds, efds;
	long selret;
	struct timeval tv;
	int max_fd = 0, sets = 0;
	zend_long sec = 0, usec = 0;
	zend_bool secnull, usecnull;
	int set_count, max_set_count = 0;

	ZEND_PARSE_PARAMETERS_START(4,5)
		Z_PARAM_ARRAY_EX2(r_arr, 1, 1, 0)
		Z_PARAM_ARRAY_EX2(w_arr, 1, 1, 0)
		Z_PARAM_ARRAY_EX2(e_arr, 1, 1, 0)
		Z_PARAM_LONG_EX(sec, secnull, 1, 0)
		Z_PARAM_OPTIONAL
		Z_PARAM_LONG(usec)
	ZEND_PARSE_PARAMETERS_END();

	FD_ZERO(&rfds);
	FD_ZERO(&wfds);
	FD_ZERO(&efds);

	if(r_arr != NULL) {
		set_count = _rawnet_array_to_fd(1, r_arr, &rfds, &max_fd);
		if(set_count > max_set_count)
			max_set_count = set_count;
		sets += set_count;
	}

	if(w_arr != NULL) {
		set_count = _rawnet_array_to_fd(2, w_arr, &wfds, &max_fd);
		if(set_count > max_set_count)
			max_set_count = set_count;
		sets += set_count;
	}

	if(e_arr != NULL) {
		set_count = _rawnet_array_to_fd(3, e_arr, &efds, &max_fd);
		if(set_count > max_set_count)
			max_set_count = set_count;
		sets += set_count;
	}

	if(!sets) {
		php_error_docref(NULL, E_WARNING, "No valid rawnet resources were passed");
		RETURN_FALSE;
	}

	PHP_SAFE_MAX_FD(max_fd, max_set_count);

	bzero(&tv, sizeof(tv));

	if(sec < 0) {
		php_error_docref(NULL, E_WARNING, "The seconds parameter must be equal to or greater than 0");
		RETURN_FALSE;
	}

	tv.tv_sec = sec;

	if(usec < 0) {
		php_error_docref(NULL, E_WARNING, "The microseconds parameter must be equal to or greater than 0");
		RETURN_FALSE;
	}

	tv.tv_usec = usec;

	if((selret = select(max_fd + 1, &rfds, &wfds, &efds, &tv)) < 0) {
		php_error_docref(NULL, E_WARNING, "Unable to select [%d]: %s (max_fd=%d)", errno, strerror(errno), max_fd);
		RETURN_FALSE;
	}

	if(r_arr != NULL)
		_rawnet_fd_to_array(1, r_arr, &rfds);

	if(w_arr != NULL)
		_rawnet_fd_to_array(2, w_arr, &wfds);

	if(e_arr != NULL)
		_rawnet_fd_to_array(3, e_arr, &efds);

	RETURN_LONG(selret);
}
/* }}}*/

/* {{{ void rawnet_listen( resource $rn, int $port, [ int $backlog = 10 ] )
 */
PHP_FUNCTION(rawnet_listen) {

	php_rawnet *res;
	zval *zid;
	zend_long port = -1, backlog = -1;
	struct sockaddr_in addr;
	int opt = 1;
	char errmsg[255];

	ZEND_PARSE_PARAMETERS_START(2,3)
		Z_PARAM_OBJECT_OF_CLASS(zid, rawnet_ce)
		Z_PARAM_LONG(port)
		Z_PARAM_OPTIONAL
		Z_PARAM_LONG(backlog)
	ZEND_PARSE_PARAMETERS_END();

	res = Z_RAWNET_P(zid);

	if(port < 1) {
		snprintf(errmsg, sizeof(errmsg), "Invalid port number %d", port);
		RETURN_STRING(errmsg);
	}

	res->port = port;
	res->socket = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(res->port);
	addr.sin_addr.s_addr = INADDR_ANY;

	if(setsockopt(res->socket, SOL_SOCKET, SO_REUSEADDR, (char *) &opt, sizeof(opt)) < 0){
		snprintf(errmsg, sizeof(errmsg), "Unable to set socket option SO_REUSEADDR (%d: %s)", errno, strerror(errno));
		goto cleanup;
	}

	if(bind(res->socket, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
		snprintf(errmsg, sizeof(errmsg), "Unable to bind socket to port %d (%d: %s)", res->port, errno, strerror(errno));
		goto cleanup;
	}

	if(res->blocking == 0) {
		if(_rawnet_nonblock(res->socket, 1) < 0) {
			snprintf(errmsg, sizeof(errmsg), "Unable to set socket to none-blocking");
			goto cleanup;
		}
	}

	// If no backlog was specified. Default it to 10
	if(backlog < 0)
		backlog = 10;

	if(listen(res->socket, backlog) != 0)  {
		snprintf(errmsg, sizeof(errmsg), "Unable to listen on port %d: (%d: %s)", res->port, errno, strerror(errno));
		goto cleanup;
	}

	RETURN_TRUE;

	cleanup:

	close(res->socket);
	RETURN_STRING(errmsg);
}
/* }}}*/

/* {{{ mixed rawnet_accept( resource $rn )
 */
PHP_FUNCTION(rawnet_accept) {

	php_rawnet *res, *retres;
	zval *zid;
	socklen_t i;
	int socket;
	struct sockaddr_in peer;
	char errmsg[255];

	ZEND_PARSE_PARAMETERS_START(1,1)
		Z_PARAM_OBJECT_OF_CLASS(zid, rawnet_ce)
	ZEND_PARSE_PARAMETERS_END();

	res = Z_RAWNET_P(zid);

	if(res->socket == -1) {
		snprintf(errmsg, sizeof(errmsg), "There is no valid socket in resource object");
		RETURN_STRING(errmsg);
	}

	i = sizeof(peer);
	if((socket = accept(res->socket, (struct sockaddr *) &peer, &i)) == -1) {
		snprintf(errmsg, sizeof(errmsg), "Unable to accept client socket: (%d: %s)", errno, strerror(errno));
		RETURN_STRING(errmsg);
	}

	object_init_ex(return_value, rawnet_ce);
	retres = Z_RAWNET_P(return_value);

	retres->blocking = 1;
	retres->connecting = 0;
	retres->socket = socket;
	retres->port = ntohs(peer.sin_port);
	retres->ssl = NULL;
	retres->ctx = res->ctx;
	retres->ctx_init = 0;
	retres->peer_cert = NULL;
	retres->peer_cert_cn = NULL;
	retres->peer_cert_serial = NULL;
	retres->peer_cert_fingerprint = NULL;

	snprintf(retres->hostname, sizeof(retres->hostname), "%s", (char *)inet_ntoa(peer.sin_addr));
}
/* }}}*/

/* {{{ void rawnet_close( resource $rn )
 */
PHP_FUNCTION(rawnet_close) {

	php_rawnet *res;
	zval *zid;

	ZEND_PARSE_PARAMETERS_START(1,1)
		Z_PARAM_OBJECT_OF_CLASS(zid, rawnet_ce)
	ZEND_PARSE_PARAMETERS_END();

	res = Z_RAWNET_P(zid);

	if(res->socket == -1)
		RETURN_TRUE;

	close(res->socket);
	res->socket = -1;

	RETURN_TRUE;

}
/* }}}*/

/* {{{ void rawnet_ssl_connect( resource $rn, [ string $certificate, string $privatekey, string $cacertificate ] )
 */
PHP_FUNCTION(rawnet_ssl_connect) {

	php_rawnet *res;
	zval *zid;
	zend_string *certificate, *privatekey, *cacertificate;
	char errmsg[256], tmperr[256], sslerror[256], peer_CN[256];
	int ret, errnr, tmplen, j;
	X509 *peer_cert = NULL;
	unsigned int n;
	unsigned char md[255];

	ZEND_PARSE_PARAMETERS_START(1,4)
		Z_PARAM_OBJECT_OF_CLASS(zid, rawnet_ce)
		Z_PARAM_OPTIONAL
		Z_PARAM_STR(certificate)
		Z_PARAM_STR(privatekey)
		Z_PARAM_STR(cacertificate)
	ZEND_PARSE_PARAMETERS_END();

	res = Z_RAWNET_P(zid);

	if(res->socket == -1) {
		snprintf(errmsg, sizeof(errmsg), "There is no valid socket in resource object");
		RETURN_STRING(errmsg);
	}

	if(res->ctx == NULL) {
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
		if((res->ctx = SSL_CTX_new(TLSv1_2_client_method())) == NULL) {
#else
		if((res->ctx = SSL_CTX_new(TLS_client_method())) == NULL) {
#endif
			snprintf(errmsg, sizeof(errmsg), "Unable to create SSL-CTX");
			goto cleanup;
		}
		res->ctx_init = 1;
	}

	if(certificate != NULL && ZSTR_LEN(certificate) > 0) {

		if(privatekey == NULL || ZSTR_LEN(privatekey) == 0) {
			snprintf(errmsg, sizeof(errmsg), "Client certificate provided but no private key");
			goto cleanup;
		}

		if(SSL_CTX_use_certificate_file(res->ctx, ZSTR_VAL(certificate), SSL_FILETYPE_PEM) <= 0) {
			snprintf(errmsg, sizeof(errmsg), "Unable to load client certificate: %s (%s)", ZSTR_VAL(certificate), ERR_error_string(ERR_get_error(), NULL));
			goto cleanup;
		}

		if(SSL_CTX_use_PrivateKey_file(res->ctx, ZSTR_VAL(privatekey), SSL_FILETYPE_PEM) <= 0) {
			snprintf(errmsg, sizeof(errmsg), "Unable to load private key: %s (%s)", ZSTR_VAL(privatekey), ERR_error_string(ERR_get_error(), NULL));
			goto cleanup;
		}

		// Verify private key
		if(!SSL_CTX_check_private_key(res->ctx))  {
			snprintf(errmsg, sizeof(errmsg), "The private key does not match provided client certificate");
			goto cleanup;
		}

	}

	if(cacertificate != NULL) {
		if(!(SSL_CTX_load_verify_locations(res->ctx, ZSTR_VAL(cacertificate), 0))) {
			snprintf(errmsg, sizeof(errmsg), "Unable to load CA-certificate: %s (%s)", ZSTR_VAL(cacertificate), ERR_error_string(ERR_get_error(), NULL));
			goto cleanup;
		}
	}

	if(res->ssl == NULL) {
		SSL_CTX_set_verify(res->ctx, SSL_VERIFY_PEER, NULL);
		res->ssl = SSL_new(res->ctx);
		SSL_set_fd(res->ssl, res->socket);
		SSL_set_connect_state(res->ssl);
	}

	if((ret = SSL_connect(res->ssl)) != 1) {

		errnr = SSL_get_error(res->ssl, ret);
		switch(errnr) {
			case SSL_ERROR_SYSCALL:
				if (errno == EWOULDBLOCK || errno == EAGAIN) {
					RETURN_FALSE;
				}
				ERR_error_string(ERR_get_error(), sslerror);
				snprintf(tmperr, sizeof(tmperr), "SSL_ERROR_SYSCALL: Errno: %d, Errstr: %s,  %d: %s", errno, strerror(errno), ERR_get_error(), sslerror);
			break;
			case SSL_ERROR_WANT_READ:
			case SSL_ERROR_WANT_WRITE:
				RETURN_FALSE;
			case SSL_ERROR_ZERO_RETURN:
				snprintf(tmperr, sizeof(tmperr), "SSL_ERROR_ZERO_RETURN");
			break;
			case SSL_ERROR_WANT_CONNECT:
				snprintf(tmperr, sizeof(tmperr), "SSL_ERROR_WANT_CONNECT");
			break;
			case SSL_ERROR_WANT_X509_LOOKUP:
				snprintf(tmperr, sizeof(tmperr), "SSL_ERROR_WANT_X509_LOOKUP");
			break;
			case SSL_ERROR_SSL:
				ERR_error_string(ERR_get_error(), sslerror);
				snprintf(tmperr, sizeof(tmperr), "SSL_ERROR_SSL: %d: %s", ERR_get_error(), sslerror);
			break;
			default:
				snprintf(tmperr, sizeof(tmperr), "Unknown error: %d", errnr);
			break;
		}

		snprintf(errmsg, sizeof(errmsg), "Connection to %s failed: %s (%d) %d", res->hostname, tmperr, errnr, ret);
		goto cleanup;
	}

	peer_cert = SSL_get_peer_certificate(res->ssl);
	if(peer_cert == NULL) {
		snprintf(errmsg, sizeof(errmsg), "Peer did not send a certificate");
		goto cleanup;
	}

	// Verify certificate dates
	if(X509_cmp_current_time(X509_get_notBefore(peer_cert)) >= 0) {
		snprintf(errmsg, sizeof(errmsg), "Peer certificate is not valid yet");
		goto cleanup;
	} else if(X509_cmp_current_time(X509_get_notAfter(peer_cert)) <= 0) {
		snprintf(errmsg, sizeof(errmsg), "Peer certificate has expired");
		goto cleanup;
	}

	_rawnet_get_cert_data(peer_cert, res);
	_rawnet_get_cert_cn(peer_cert, res);
	_rawnet_get_cert_serial(peer_cert, res);
	_rawnet_get_cert_fingerprint(peer_cert, res);

	X509_free(peer_cert);

	RETURN_TRUE;

	cleanup:

	if(res->ssl != NULL) {
		SSL_shutdown(res->ssl);
		SSL_free(res->ssl);
		res->ssl = NULL;
	}

	if(peer_cert != NULL)
		X509_free(peer_cert);

	RETURN_STRING(errmsg);

}
/* }}}*/

/* {{{ void rawnet_ssl_listen( resource $rn )
 */
PHP_FUNCTION(rawnet_ssl_listen) {

	php_rawnet *res;
	zval *zid;
	char errmsg[255], ssl_errbuf[255];
	zend_string *certificate, *privatekey, *cacertificate;
	zend_bool forceclientcert = 0;

	ZEND_PARSE_PARAMETERS_START(4,5)
		Z_PARAM_OBJECT_OF_CLASS(zid, rawnet_ce)
		Z_PARAM_STR(certificate)
		Z_PARAM_STR(privatekey)
		Z_PARAM_STR(cacertificate)
		Z_PARAM_OPTIONAL
		Z_PARAM_BOOL(forceclientcert)
	ZEND_PARSE_PARAMETERS_END();


	res = Z_RAWNET_P(zid);

	if(res->ctx == NULL) {
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
		res->ctx = SSL_CTX_new(TLSv1_2_server_method());
#else
		res->ctx = SSL_CTX_new(TLS_server_method());
#endif
		if(res->ctx == NULL) {
			snprintf(errmsg, sizeof(errmsg), "Unable to create SSL-CTX");
			RETURN_STRING(errmsg);
		}
		res->ctx_init = 1;
	}

	if(SSL_CTX_use_certificate_file(res->ctx, ZSTR_VAL(certificate), SSL_FILETYPE_PEM) <= 0) {
		snprintf(errmsg, sizeof(errmsg), "Unable to load certificate: %s (%s)", ZSTR_VAL(certificate), ERR_error_string(ERR_get_error(), NULL));
		goto cleanup;
	}

	if(SSL_CTX_use_PrivateKey_file(res->ctx, ZSTR_VAL(privatekey), SSL_FILETYPE_PEM) <= 0) {
		snprintf(errmsg, sizeof(errmsg), "Unable to load private key: %s (%s)", ZSTR_VAL(privatekey), ERR_error_string(ERR_get_error(), NULL));
		goto cleanup;
	}

	if(!(SSL_CTX_load_verify_locations(res->ctx, ZSTR_VAL(cacertificate), 0))) {
		snprintf(errmsg, sizeof(errmsg), "Unable to load CA certificate: %s (%s)", ZSTR_VAL(cacertificate), ERR_error_string(ERR_get_error(), NULL));
		goto cleanup;
	}

	// Verify private key
	if(!SSL_CTX_check_private_key(res->ctx))  {
		snprintf(errmsg, sizeof(errmsg), "The private key does not match provided client certificate");
		goto cleanup;
	}

	if(forceclientcert) {
		SSL_CTX_set_verify(res->ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
	}

	RETURN_TRUE;

	cleanup:

	SSL_CTX_free(res->ctx);
	res->ctx = NULL;
	res->ctx_init = 0;
	RETURN_STRING(errmsg);
}
/* }}}*/

/* {{{ void rawnet_ssl_accept( resource $rn, [ bool $forceclientcert = FALSE ] )
 */
PHP_FUNCTION(rawnet_ssl_accept) {

	php_rawnet *res;
	zval *zid;
	char errmsg[255];
	zend_bool forceclientcert = 0;
	int ssl_errcode, ret;
	X509 *peer_cert = NULL;

	ZEND_PARSE_PARAMETERS_START(1,2)
		Z_PARAM_OBJECT_OF_CLASS(zid, rawnet_ce)
		Z_PARAM_OPTIONAL
		Z_PARAM_BOOL(forceclientcert)
	ZEND_PARSE_PARAMETERS_END();

	res = Z_RAWNET_P(zid);

	if(res->ctx == NULL) {
		snprintf(errmsg, sizeof(errmsg), "No CTX created on socket accept");
		RETURN_STRING(errmsg);
	}

	if(res->ssl == NULL) {

		res->ssl = SSL_new(res->ctx);
		if(res->ssl == NULL) {
			snprintf(errmsg, sizeof(errmsg), "SSL_new() failed: %s", ERR_error_string(ERR_get_error(), NULL));
			goto cleanup;
		}

		if(!SSL_set_fd(res->ssl, res->socket)) {
			snprintf(errmsg, sizeof(errmsg), "SSL_set_fd() failed on client socket: %s", ERR_error_string(ERR_get_error(), NULL));
			goto cleanup;
		}

		SSL_set_accept_state(res->ssl);
	}


	if((ret = SSL_accept(res->ssl)) < 1) {
		ssl_errcode = SSL_get_error(res->ssl, 0);
		switch(ssl_errcode) {
			case SSL_ERROR_SYSCALL:
				if (errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN) {
					RETURN_FALSE;
				} else {
					snprintf(errmsg, sizeof(errmsg), "SSL_ERROR_SYSCALL: %s", ERR_error_string(ERR_get_error(), NULL));
					RETURN_STRING(errmsg);
				}
			break;
			case SSL_ERROR_WANT_READ:
			case SSL_ERROR_WANT_WRITE:
				RETURN_FALSE;
			case SSL_ERROR_SSL:
				snprintf(errmsg, sizeof(errmsg), "SSL_ERROR_SSL: %s", ERR_error_string(ERR_get_error(), NULL));
				RETURN_STRING(errmsg);
			break;
			case SSL_ERROR_ZERO_RETURN:
				snprintf(errmsg, sizeof(errmsg), "SSL_ERROR_ZERO_RETURN");
				RETURN_STRING(errmsg);
			break;
			default:
				snprintf(errmsg, sizeof(errmsg), "Unknown error from SSL_accept(): %d (%s)", ssl_errcode, ERR_error_string(ERR_get_error(), NULL));
				RETURN_STRING(errmsg);
		}
	}

	peer_cert = SSL_get_peer_certificate(res->ssl);
	if(peer_cert == NULL) {
		if(forceclientcert) {
			snprintf(errmsg, sizeof(errmsg), "The client did not send a client certificate");
			goto cleanup;
		}
	} else {

		if((ret = SSL_get_verify_result(res->ssl)) != X509_V_OK) {
			snprintf(errmsg, sizeof(errmsg), "Unable to verify client certificate: %d", ret);
			goto cleanup;			
		}

		_rawnet_get_cert_data(peer_cert, res);
		_rawnet_get_cert_cn(peer_cert, res);
		_rawnet_get_cert_serial(peer_cert, res);
		_rawnet_get_cert_fingerprint(peer_cert, res);

	}

	X509_free(peer_cert);

	RETURN_TRUE;

	cleanup:

	if(res->ssl != NULL) {
		SSL_shutdown(res->ssl);
		close(res->socket);
		SSL_free(res->ssl);
		res->ssl = NULL;
		res->socket = -1;
	}

	if(peer_cert != NULL)
		X509_free(peer_cert);

	RETURN_STRING(errmsg);
}
/* }}}*/


/* {{{ void rawnet_ssl_close( resource $rn )
 */
PHP_FUNCTION(rawnet_ssl_close) {

	php_rawnet *res;
	zval *zid;

	ZEND_PARSE_PARAMETERS_START(1,1)
		Z_PARAM_OBJECT_OF_CLASS(zid, rawnet_ce)
	ZEND_PARSE_PARAMETERS_END();

	res = Z_RAWNET_P(zid);

	if(res->ssl != NULL) {
		SSL_shutdown(res->ssl);
		SSL_free(res->ssl);
		res->ssl = NULL;
	}

	if(res->ctx_init == 1 && res->ctx != NULL) {
		SSL_CTX_free(res->ctx);
		res->ctx = NULL;
		res->ctx_init = 0;
	}

	RETURN_TRUE;
}
/* }}}*/

/* {{{ mixed rawnet_set_blocking( resource $rn, bool $mode )
 */
PHP_FUNCTION(rawnet_set_blocking) {

	php_rawnet *res;
	zval *zid;
	zend_bool mode;
	int ret;
	char errmsg[255];

	ZEND_PARSE_PARAMETERS_START(2,2)
		Z_PARAM_OBJECT_OF_CLASS(zid, rawnet_ce)
		Z_PARAM_BOOL(mode)
	ZEND_PARSE_PARAMETERS_END();

	res = Z_RAWNET_P(zid);

	if(res->socket == -1) {
			snprintf(errmsg, sizeof(errmsg), "The resource does not contain a valid socket");
			RETURN_STRING(errmsg);
	}

	res->blocking = (!mode ? 0 : 1);
	ret = _rawnet_nonblock(res->socket, !res->blocking);

	if(ret < 0) {
		if(res->blocking == 0) {
			snprintf(errmsg, sizeof(errmsg), "Unable to set socket to none-blocking");
		} else {
			snprintf(errmsg, sizeof(errmsg), "Unable to set socket to blocking");
		}
		RETURN_STRING(errmsg);
	}

	RETURN_TRUE;
}
/* }}}*/

/* {{{ array rawnet_getinfo( resource $rn )
 */
PHP_FUNCTION(rawnet_getinfo) {

	php_rawnet *res;
	zval *zid;

	ZEND_PARSE_PARAMETERS_START(1,1)
		Z_PARAM_OBJECT_OF_CLASS(zid, rawnet_ce)
	ZEND_PARSE_PARAMETERS_END();

	res = Z_RAWNET_P(zid);

	array_init(return_value);

	CAAL("socket", res->socket);
	CAAS("hostname", res->hostname);
	CAAL("port", res->port);
	CAAL("blocking", res->blocking);

	CAAS("peer_cert", res->peer_cert);
	CAAS("peer_cert_cn", res->peer_cert_cn);
	CAAS("peer_cert_serial", res->peer_cert_serial);
	CAAS("peer_cert_fingerprint", res->peer_cert_fingerprint);
}
/* }}}*/


/* {{{ array rawnet_getinfo( resource $rn )
 */
PHP_FUNCTION(rawnet_is_connecting) {

	php_rawnet *res;
	zval *zid;

	ZEND_PARSE_PARAMETERS_START(1,1)
		Z_PARAM_OBJECT_OF_CLASS(zid, rawnet_ce)
	ZEND_PARSE_PARAMETERS_END();

	res = Z_RAWNET_P(zid);

	if(res->connecting)
		RETURN_TRUE;

	RETURN_FALSE;
}
/* }}}*/

/* {{{ PHP_RINIT_FUNCTION
 */
PHP_RINIT_FUNCTION(rawnet)
{
#if defined(ZTS) && defined(COMPILE_DL_RAWNET)
	ZEND_TSRMLS_CACHE_UPDATE();
#endif

	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MINFO_FUNCTION
 */
PHP_MINFO_FUNCTION(rawnet)
{
	php_info_print_table_start();
	php_info_print_table_header(2, "rawnet support", "enabled");
	php_info_print_table_end();
}
/* }}} */

static void _php_rawnet_close(zend_resource *rsrc) {

	php_rawnet *res = (php_rawnet *) rsrc->ptr;

	if(res->peer_cert != NULL) {
		efree(res->peer_cert);
		res->peer_cert = NULL;
	}

	if(res->peer_cert_cn != NULL) {
		efree(res->peer_cert_cn);
		res->peer_cert_cn = NULL;
	}

	if(res->peer_cert_serial != NULL) {
		efree(res->peer_cert_serial);
		res->peer_cert_serial = NULL;
	}

	if(res->peer_cert_fingerprint != NULL) {
		efree(res->peer_cert_fingerprint);
		res->peer_cert_fingerprint = NULL;
	}

	efree(res);
}


PHP_MINIT_FUNCTION(rawnet) {

	_rawnet_init_openssl();

	zend_class_entry ce_rawnet;
	INIT_CLASS_ENTRY(ce_rawnet, "Rawnet", class_Rawnet_methods);
	rawnet_ce = zend_register_internal_class(&ce_rawnet);
	rawnet_ce->ce_flags |= ZEND_ACC_FINAL | ZEND_ACC_NO_DYNAMIC_PROPERTIES | ZEND_ACC_NOT_SERIALIZABLE;
	rawnet_ce->create_object = rawnet_create_object;

	memcpy(&rawnet_object_handlers, &std_object_handlers, sizeof(zend_object_handlers));
	rawnet_object_handlers.offset = XtOffsetOf(php_rawnet, std);
	rawnet_object_handlers.free_obj = rawnet_free_obj;
	rawnet_object_handlers.get_constructor = rawnet_get_constructor;
	rawnet_object_handlers.clone_obj = NULL;
	rawnet_object_handlers.get_gc = rawnet_get_gc;
	rawnet_object_handlers.compare = zend_objects_not_comparable;

	return SUCCESS;
}

/* {{{ arginfo
 */
ZEND_BEGIN_ARG_INFO(arginfo_rawnet_init, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_rawnet_connect, 0)
	ZEND_ARG_INFO(0, res)
	ZEND_ARG_INFO(0, hostname)
	ZEND_ARG_INFO(0, port)
	ZEND_ARG_INFO(0, timeout_sec)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_rawnet_close, 0)
	ZEND_ARG_INFO(0, res)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_rawnet_read, 0)
	ZEND_ARG_INFO(0, res)
	ZEND_ARG_INFO(0, rlen)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_rawnet_write, 0)
	ZEND_ARG_INFO(0, res)
	ZEND_ARG_INFO(0, wdata)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_rawnet_select, 0, 0, 4)
	ZEND_ARG_INFO(1, aread)
	ZEND_ARG_INFO(1, awrite)
	ZEND_ARG_INFO(1, aexcept)
	ZEND_ARG_INFO(0, sec)
	ZEND_ARG_INFO(0, usec)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_rawnet_listen, 0)
	ZEND_ARG_INFO(0, res)
	ZEND_ARG_INFO(0, port)
	ZEND_ARG_INFO(0, backlog)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_rawnet_accept, 0)
	ZEND_ARG_INFO(0, res)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_rawnet_ssl_connect, 0)
	ZEND_ARG_INFO(0, res)
	ZEND_ARG_INFO(0, certificate)
	ZEND_ARG_INFO(0, privatekey)
	ZEND_ARG_INFO(0, cacertificate)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_rawnet_ssl_listen, 0)
	ZEND_ARG_INFO(0, res)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_rawnet_ssl_accept, 0)
	ZEND_ARG_INFO(0, res)
	ZEND_ARG_INFO(0, forceclientcert)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_rawnet_ssl_close, 0)
	ZEND_ARG_INFO(0, res)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_rawnet_set_blocking, 0)
	ZEND_ARG_INFO(0, res)
	ZEND_ARG_INFO(0, mode)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_rawnet_getinfo, 0)
	ZEND_ARG_INFO(0, res)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_rawnet_is_connecting, 0)
	ZEND_ARG_INFO(0, res)
ZEND_END_ARG_INFO()

/* }}} */

/* {{{ rawnet_functions[]
 */
static const zend_function_entry rawnet_functions[] = {
	PHP_FE(rawnet_init,		arginfo_rawnet_init)
	PHP_FE(rawnet_connect,		arginfo_rawnet_connect)
	PHP_FE(rawnet_read,		arginfo_rawnet_read)
	PHP_FE(rawnet_write,		arginfo_rawnet_write)
	PHP_FE(rawnet_select,		arginfo_rawnet_select)
	PHP_FE(rawnet_listen,		arginfo_rawnet_listen)
	PHP_FE(rawnet_accept,		arginfo_rawnet_accept)
	PHP_FE(rawnet_close,		arginfo_rawnet_close)
	PHP_FE(rawnet_ssl_connect,	arginfo_rawnet_ssl_connect)
	PHP_FE(rawnet_ssl_listen,	arginfo_rawnet_ssl_listen)
	PHP_FE(rawnet_ssl_accept,	arginfo_rawnet_ssl_accept)
	PHP_FE(rawnet_ssl_close,	arginfo_rawnet_ssl_close)
	PHP_FE(rawnet_set_blocking,	arginfo_rawnet_set_blocking)
	PHP_FE(rawnet_getinfo,		arginfo_rawnet_getinfo)
	PHP_FE(rawnet_is_connecting,	arginfo_rawnet_is_connecting)
	PHP_FE_END
};
/* }}} */

/* {{{ rawnet_module_entry
 */
zend_module_entry rawnet_module_entry = {
	STANDARD_MODULE_HEADER,
	"rawnet",				/* Extension name */
	rawnet_functions,			/* zend_function_entry */
	PHP_MINIT(rawnet),			/* PHP_MINIT - Module initialization */
	NULL,					/* PHP_MSHUTDOWN - Module shutdown */
	PHP_RINIT(rawnet),			/* PHP_RINIT - Request initialization */
	NULL,					/* PHP_RSHUTDOWN - Request shutdown */
	PHP_MINFO(rawnet),			/* PHP_MINFO - Module info */
	PHP_RAWNET_VERSION,			/* Version */
	STANDARD_MODULE_PROPERTIES
};
/* }}} */

#ifdef COMPILE_DL_RAWNET
# ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE()
# endif
ZEND_GET_MODULE(rawnet)
#endif
