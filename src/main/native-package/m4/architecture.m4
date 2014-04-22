
  AC_MSG_CHECKING(which arch to build for)
  AC_ARG_WITH([arch],
  [AS_HELP_STRING([--with-arch@<:@=ARCH@:>@],
    [Build for the specified architecture. Pick from: i386, x86_64.])],
  [
    AS_IF(test -n "$withval", [
      ARCH="$withval"
      AC_MSG_RESULT([yes, archs: $ARCH])
    ])
  ],[
    ARCH=""
    AC_MSG_RESULT([no])
  ])
  AS_IF(test "$ARCH" = "i386", [
    FLAGS="-m32"
  ], test "ARCH" = "x86_64", [
    FLAGS="-m64"
  ], [
    FLAGS=""
  ])
  AS_IF(test -n "$FLAGS", [
    CFLAGS="$FLAGS $CFLAGS"
    CXXFLAGS="$FLAGS $CXXFLAGS"
    LDFLAGS="$FLAGS $ARCH $LDFLAGS"
    AC_SUBST(CFLAGS)
    AC_SUBST(CXXFLAGS)
    AC_SUBST(LDFLAGS)
  ])
