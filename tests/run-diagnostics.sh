#!/bin/sh
set -eu
core=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
runtime=${1:?Usage: run-diagnostics.sh /path/to/hev-task-system}
work=$(mktemp -d)
trap '[ -n "${KEEP_BUILD:-}" ] || rm -rf "$work"' EXIT HUP INT TERM
printf '%s\n' "Build directory: $work"
mkdir "$work/runtime"
cp -R "$runtime/include" "$runtime/src" "$runtime/Makefile" "$runtime/build.mk" "$runtime/configs.mk" "$work/runtime/"
make -s -C "$work/runtime" -j4 static > "$work/runtime-build.log" 2>&1 || { cat "$work/runtime-build.log"; exit 1; }
udp_flags=
if rg -q 'hev_socks5_udp_sendto' "$core/src/hev-socks5-udp.h"; then
    udp_flags=-DCORE_LEGACY_UDP
fi
${CC:-cc} $udp_flags -g -O1 -Wall -Wextra -Werror -Wno-unused-parameter -Wno-sign-compare \
    -I"$core/src" -I"$core/include" -I"$work/runtime/include" \
    "$core/tests/diagnostics.c" "$core"/src/*.c \
    "$work/runtime/bin/libhev-task-system.a" -pthread -o "$work/diagnostics"
"$work/diagnostics" "$work/diagnostics.log"
