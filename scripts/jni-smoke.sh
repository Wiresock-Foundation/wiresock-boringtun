#!/usr/bin/env bash
#
# Run the JNI bindings against a real JVM.
#
# `src/jni.rs` cannot be covered by `cargo test`: its entry points take a
# `JNIEnv` and are only reachable through JNI dispatch, so a green test run
# proves the bindings compile and nothing more. That gap let a jni 0.22
# migration turn a thrown `ArrayIndexOutOfBoundsException` into a silent `null`
# -- caught only because a reviewer built a library and ran a Java harness by
# hand. This is that harness, made repeatable.
#
# Requires a JDK (javac + java) and cargo. Used by the `jni-smoke` CI job and
# runnable locally with no arguments.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

command -v javac >/dev/null || { echo "javac not found; install a JDK" >&2; exit 2; }
command -v java  >/dev/null || { echo "java not found; install a JDK" >&2; exit 2; }

echo "==> building the cdylib with jni-bindings"
cargo build -p boringtun --features jni-bindings

# The library name differs per platform, and so does the variable the loader
# consults. `System.loadLibrary("boringtun")` looks for exactly these.
case "$(uname -s)" in
  Darwin) LIBNAME=libboringtun.dylib ;;
  MINGW*|MSYS*|CYGWIN*) LIBNAME=boringtun.dll ;;
  *) LIBNAME=libboringtun.so ;;
esac

LIBDIR="$ROOT/target/debug"
[ -f "$LIBDIR/$LIBNAME" ] || {
  echo "expected $LIBDIR/$LIBNAME after the build; found:" >&2
  ls -1 "$LIBDIR" | grep -i boringtun >&2 || true
  exit 1
}
echo "    $LIBDIR/$LIBNAME"

OUT=$(mktemp -d)
trap 'rm -rf "$OUT"' EXIT

echo "==> compiling the harness"
javac -d "$OUT" "$ROOT/boringtun/tests/jni/com/cloudflare/app/boringtun/BoringTunJNI.java"

echo "==> running against $(java -version 2>&1 | head -1)"
# -Xcheck:jni makes the JVM validate every JNI call this library makes, which
# is the point of running it here rather than trusting a compile.
java -Xcheck:jni \
     -Djava.library.path="$LIBDIR" \
     -cp "$OUT" \
     com.cloudflare.app.boringtun.BoringTunJNI
