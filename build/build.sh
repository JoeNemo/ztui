#!/bin/sh

# This program and the accompanying materials are
# made available under the terms of the Eclipse Public License v2.0 which accompanies
# this distribution, and is available at https://www.eclipse.org/legal/epl-v20.html
#
# SPDX-License-Identifier: EPL-2.0
#
# Copyright Contributors to the Zowe Project.

# Build ztui tools.
# Uses xlclang++ (for zoslib C++) linking against zopen ncurses (ASCII).
# Follows the hybrid EBCDIC/ASCII pattern.

# Source zopen environment for ncurses paths (before set -e, it may return non-zero)
export ZOPEN_ROOTFS=$HOME/zopen
. $HOME/zopen/etc/zopen-config --override-zos-tools 2>/dev/null || true

set -e

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SRC="${REPO}/src"
COMMON="${REPO}/deps/zowe-common-c"

# ncurses paths from zopen
NC_BASE="$ZOPEN_ROOTFS/usr/local"
NC_INC="${NC_BASE}/include/ncursesw"
NC_LIB="${NC_BASE}/lib"

# Verify ncurses is available
if [ ! -f "${NC_INC}/ncurses.h" ]; then
  echo "ERROR: ncurses.h not found at ${NC_INC}"
  echo "Install ncurses via: zopen install ncurses"
  exit 1
fi
if [ ! -f "${NC_LIB}/libncursesw.a" ]; then
  echo "ERROR: libncursesw.a not found at ${NC_LIB}"
  exit 1
fi

# zoslib — needed for hybrid EBCDIC/ASCII bridging
ZOSLIB_INC="$ZOPEN_ROOTFS/usr/local/include/zos"
ZOSLIB_LIB="$ZOPEN_ROOTFS/usr/local/lib"

if [ ! -f "${ZOSLIB_LIB}/libzoslib.x" ]; then
  echo "ERROR: libzoslib.x not found at ${ZOSLIB_LIB}"
  echo "Install zoslib via: zopen install zoslib"
  exit 1
fi

XLC_OPTS='-q64 "-Wc,float(ieee),longname,langlvl(extc99),gonum,goff,ASM,asmlib('"'"'CEE.SCEEMAC'"'"','"'"'SYS1.MACLIB'"'"','"'"'SYS1.MODGEN'"'"')"'
DEFINES="-D_OPEN_SYS_FILE_EXT=1 -D_OPEN_SYS=1 -D_XOPEN_SOURCE=600 -D_OPEN_THREADS=1"
INCLUDES="-I ${COMMON}/h -I ${SRC} -I /usr/include/zos -I ${NC_INC}"

# Common library sources from zowe-common-c
COMMON_SRCS="${SRC}/nctui.c \
  ${COMMON}/c/jobservice.c \
  ${COMMON}/c/logreader.c \
  ${COMMON}/c/ssi.c \
  ${COMMON}/c/alloc.c \
  ${COMMON}/c/zos.c \
  ${COMMON}/c/timeutls.c \
  ${COMMON}/c/utils.c \
  ${COMMON}/c/collections.c \
  ${COMMON}/c/logging.c \
  ${COMMON}/c/recovery.c \
  ${COMMON}/c/scheduling.c \
  ${COMMON}/c/le.c \
  ${COMMON}/c/dynalloc.c"

# Link flags: full paths to .a archives (xlclang++ doesn't support -L/-l)
LINK_FLAGS="${NC_LIB}/libpanelw.a ${NC_LIB}/libncursesw.a ${ZOSLIB_LIB}/libzoslib.x"

build_one() {
  _prog="$1"
  _src="$2"
  _extra_src="$3"
  echo ""
  echo "=== Building $_prog ==="
  _objs=""
  for _f in "$_src" $_extra_src $COMMON_SRCS; do
    _base=$(basename "$_f" .c)
    _obj="${_base}.o"
    eval xlclang $XLC_OPTS $DEFINES $INCLUDES -c "$_f" -o "$_obj"
    rc=$?
    if [ $rc -gt 4 ]; then
      echo "  COMPILE FAILED: $_f rc=$rc"
      rm -f $_objs
      exit $rc
    fi
    _objs="$_objs $_obj"
  done
  # Link
  eval xlclang++ -q64 -o "$_prog" $_objs $LINK_FLAGS
  rc=$?
  rm -f $_objs
  if [ $rc -eq 0 ]; then
    echo "  OK: ./$_prog"
    ls -la "$_prog"
  else
    echo "  LINK FAILED rc=$rc"
    exit $rc
  fi
}

echo "Building ztui tools"
echo "Repo:       $REPO"
echo "Source:     $SRC"
echo "Common:     $COMMON"
echo "ncurses:    ${NC_INC}"
echo "zoslib:     ${ZOSLIB_LIB}"

# ST panel (job status)
build_one nczst "${SRC}/nczst.c"

# DA panel (display active)
build_one nczda "${SRC}/nczda.c" "${SRC}/asinfo.c"

# SYSLOG browser
build_one nczlog "${SRC}/nczlog.c"

# Process viewer
build_one nczps "${SRC}/nczps.c" "${SRC}/procinfo.c"

# MVS Display command browser
build_one nczdisp "${SRC}/nczdisp.c" "${COMMON}/c/zdisplay.c"

# TSO Command Session
build_one nctso "${SRC}/nctso.c" "${SRC}/tsopipe.c"

# Memory Viewer
build_one ncmem "${SRC}/ncmem.c"

echo ""
echo "All builds complete."
