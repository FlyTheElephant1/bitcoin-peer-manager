#!/bin/sh
# Generate git_version.h on every build
OUT="$1"
HASH=$(git -C "$(dirname "$0")" rev-parse --short=12 HEAD 2>/dev/null || echo UNKNOWN_GIT_HASH)
if ! git -C "$(dirname "$0")" diff --quiet 2>/dev/null; then
  HASH="${HASH}-dirty"
fi
cat > "$OUT" << EOF
#ifndef GIT_VERSION_H
#define GIT_VERSION_H
#define GIT_COMMIT_HASH "$HASH"
#endif
EOF
