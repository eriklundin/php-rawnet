dnl config.m4 for extension rawnet

PHP_ARG_ENABLE(rawnet, whether to enable rawnet support,
[  --enable-rawnet         Enable rawnet support], no)

if test "$PHP_RAWNET" != "no"; then

	AC_PATH_PROG(PKG_CONFIG, pkg-config, no)
	AC_MSG_CHECKING(for libopenssl)

	if test -x "$PKG_CONFIG" && $PKG_CONFIG --exists openssl; then
		PHP_EVAL_LIBLINE(`$PKG_CONFIG openssl --libs`, RAWNET_SHARED_LIBADD)
	else
		AC_MSG_ERROR(pkg-config not found)
	fi

	AC_DEFINE(HAVE_RAWNET, 1, [ Have rawnet support ])
	PHP_NEW_EXTENSION(rawnet, rawnet.c, $ext_shared)
fi
