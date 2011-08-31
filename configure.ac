# Process this file with autoconf to produce a configure script.

AC_INIT([mper], [20110831], [alistair@caida.org])

AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([scamper.c])
AM_INIT_AUTOMAKE
AC_CONFIG_HEADER([config.h])

AC_PROG_LIBTOOL
AC_PROG_CC
AC_PROG_GCC_TRADITIONAL
AC_PROG_INSTALL
AC_PROG_MKDIR_P
AC_LANG(C)

if test -d "/usr/local/lib"; then
   LDFLAGS+=" -L/usr/local/lib"
fi

if test -d "/usr/local/include"; then
   CFLAGS+=" -I/usr/local/include";
fi

# Whether all the debugging output should be spewed out
AC_ARG_ENABLE([debug],
  [AS_HELP_STRING([--enable-debug], [build with debugging symbols])])

if test "x$enable_debug" != "xyes"; then
  AC_DEFINE([NDEBUG],[1],[Defined to 1 if we don't want to do any debugging])
fi

# No privilege separation
AC_ARG_ENABLE([privsep],
  [AS_HELP_STRING([--disable-privsep], [disable privilege separation])])

if test "x$enable_privsep" = xno; then
  AC_DEFINE([WITHOUT_PRIVSEP], [1], [Defined to 1 if we don't want privilege separation])
fi

# privsep parameters
AC_ARG_WITH([privsep_user],
  [AC_HELP_STRING([--with-privsep-user=USER],
    [sets user name for privsep process])],
  [privsep_user=$withval],
  [privsep_user=nobody])
AC_ARG_WITH([privsep_dir],
  [AC_HELP_STRING([--with-privsep-dir=DIR],
    [sets chroot directory for privsep process])],
  [privsep_dir=$withval],
  [privsep_dir=/var/empty])
AC_ARG_WITH([privsep_dir_owner],
  [AC_HELP_STRING([--with-privsep-dir-user=USER],
    [sets chroot directory owner])],
  [privsep_dir_user=$withval],
  [privsep_dir_user=root])
AC_ARG_WITH([privsep_dir_group],
  [AC_HELP_STRING([--with-privsep-dir-group=GROUP],
    [sets chroot directory group id])],
  [privsep_dir_group=$withval],
  [privsep_dir_group=wheel])
AC_SUBST(privsep_user)
AC_SUBST(privsep_dir)
AC_SUBST(privsep_dir_user)
AC_SUBST(privsep_dir_group)
AC_DEFINE_UNQUOTED(PRIVSEP_USER,
  ["$privsep_user"],
  [user name for privsep process])
AC_DEFINE_UNQUOTED(PRIVSEP_DIR,
  ["$privsep_dir"],
  [chroot directory for privsep process])
AC_DEFINE_UNQUOTED(PRIVSEP_DIR_USER,
  ["$privsep_dir_user"],
  [chroot directory owner])
AC_DEFINE_UNQUOTED(PRIVSEP_DIR_GROUP,
  ["$privsep_dir_group"],
  [chroot directory group id])

# Debug file support
AC_ARG_ENABLE([debug-file],
  [AS_HELP_STRING([--disable-debug-file],
    [remove support for generating a debug file])])

if test "x$enable_debug_file" = xno; then
  AC_DEFINE([WITHOUT_DEBUGFILE], [1], [Defined to 1 if we don't want to be able generate a debugfile])
fi

# dmalloc support
AC_ARG_WITH([dmalloc],
  [AS_HELP_STRING([--with-dmalloc],
     [enable support for dmalloc])])

if test "x$with_dmalloc" = xyes; then
	AC_CHECK_LIB([dmalloc],	[dmalloc_malloc],
		[
		CFLAGS+=" -DDMALLOC"
		LIBS+=-ldmalloc
		],
		[AC_MSG_FAILURE([dmalloc test failed (remove --with-dmalloc)])])

fi

# Checks for libraries.
AC_CHECK_LIB([iphlpapi], [GetIpNetTable])
AC_CHECK_LIB([ws2_32], [WSAStartup])

# Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_HEADER_TIME
AC_CHECK_HEADERS(arpa/inet.h)
AC_CHECK_HEADERS(fcntl.h)
AC_CHECK_HEADERS(limits.h)
AC_CHECK_HEADERS(netdb.h)
AC_CHECK_HEADERS(net/if_dl.h)
AC_CHECK_HEADERS(net/if_types.h)
AC_CHECK_HEADERS(netinet/in.h)
AC_CHECK_HEADERS(stdint.h)
AC_CHECK_HEADERS(stdlib.h)
AC_CHECK_HEADERS(string.h)
AC_CHECK_HEADERS(sys/ioctl.h)
AC_CHECK_HEADERS(sys/param.h)
AC_CHECK_HEADERS(sys/socket.h)
AC_CHECK_HEADERS(sys/sysctl.h)
AC_CHECK_HEADERS(sys/time.h)
AC_CHECK_HEADERS(unistd.h)
AC_CHECK_HEADERS(ifaddrs.h)

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_UID_T
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_STRUCT_TM
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_CHOWN
AC_FUNC_FORK
AC_CHECK_FUNCS(atexit)
AC_CHECK_FUNCS(daemon)
AC_CHECK_FUNCS(endpwent)
AC_CHECK_FUNCS(ftruncate)
AC_CHECK_FUNCS(gethostname)
AC_CHECK_FUNCS(gettimeofday)
AC_CHECK_FUNCS(memmove)
AC_CHECK_FUNCS(memset)
AC_CHECK_FUNCS(mkdir)
AC_CHECK_FUNCS(rmdir)
AC_CHECK_FUNCS(select)
AC_CHECK_FUNCS(socket)
AC_CHECK_FUNCS(snprintf)
AC_CHECK_FUNCS(setproctitle)
AC_CHECK_FUNCS(strcasecmp)
AC_CHECK_FUNCS(strcasestr)
AC_CHECK_FUNCS(strdup)
AC_CHECK_FUNCS(strerror)
AC_CHECK_FUNCS(strncasecmp)
AC_CHECK_FUNCS(strtol)
AC_CHECK_FUNCS(uname)
AC_CHECK_FUNCS(getifaddrs)

AC_CHECK_MEMBER([struct sockaddr.sa_len],
	[AC_DEFINE([HAVE_STRUCT_SOCKADDR_SA_LEN],[1],
	[Define if struct sockaddr has an sa_len member])],[:],
	[#include <sys/types.h>
	 #include <sys/socket.h>])

# Check for structs
AC_MSG_CHECKING([for struct ip6_ext])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#include <sys/types.h>]],
				   [[#include <netinet/in.h>]],
				   [[#include <netinet/ip6.h>]],
				   [[void foo(void) { struct ip6_ext ext; }]])],
                    [
                      AC_MSG_RESULT([yes])
                      AC_DEFINE_UNQUOTED([HAVE_STRUCT_IP6_EXT], 1, [Define to 1 if you have the `ip6_ext' struct.])
                    ],
                    [
                      AC_MSG_RESULT([no])
                      #AC_DEFINE_UNQUOTED([HAVE_STRUCT_IP6_EXT], 0, [Define to 1 if you have the `ip6_ext' struct.])
                    ]
                 )

# These libraries have to be explicitly linked in OpenSolaris (from libtrace)
AC_SEARCH_LIBS(getaddrinfo, socket, [], [], -lnsl)
AC_SEARCH_LIBS(inet_ntop, nsl, [], [], -lsocket)

AC_CONFIG_FILES([
	Makefile
])
AC_OUTPUT
