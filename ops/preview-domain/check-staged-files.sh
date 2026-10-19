#!/usr/bin/env bash
# Read-only confirmation that a failed install left only byte-identical
# application files. Does not delete, overwrite, chmod, or create anything.
set -euo pipefail
[[ "$#" == 4 ]] || { echo 'Provide package, static site, backend and parser paths.' >&2; exit 2; }
package="$1"
site="$2"
backend="$3"
parser="$4"

if [[ ! -e "$site" && ! -e "$backend" && ! -e "$parser" ]]; then
  echo FRESH
  exit 0
fi

# Partially copied or unexpected existing trees require manual inspection.
for path in "$site" "$backend" "$parser"; do
  [[ -d "$path" && ! -L "$path" ]] || {
    echo "Cannot safely reuse incomplete or linked installation: $path" >&2
    exit 1
  }
  if find "$path" -type l -print -quit | grep -q .; then
    echo "Unexpected symlink in installation: $path" >&2
    exit 1
  fi
done

# Python may create harmless __pycache__ directories during the first
# systemd start; compare all actual program/data files strictly.
for entry in "web:$site" "backend:$backend" "multipass:$parser"; do
  kind="${entry%%:*}"
  target="${entry#*:}"
  [[ -d "$package/$kind" ]] || {
    echo "Deployment package does not contain $kind" >&2
    exit 1
  }
  if ! diff -qr -x __pycache__ "$package/$kind" "$target" >/dev/null; then
    echo "Previously staged files differ from qualified package: $target" >&2
    exit 1
  fi
done
echo REUSE_VERIFIED
