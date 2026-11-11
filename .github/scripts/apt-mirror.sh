#!/bin/sh
# Some GitHub runners cannot resolve *.ubuntu.com, which breaks every apt step.
# Rewrites all apt sources to the first mirror that resolves.
set -eu

for m in https://mirrors.edge.kernel.org/ubuntu \
         https://ftp.osuosl.org/pub/ubuntu \
         https://mirror.math.princeton.edu/pub/ubuntu \
         http://archive.ubuntu.com/ubuntu; do
  host=${m#*://}
  host=${host%%/*}
  if getent hosts "$host" >/dev/null 2>&1; then
    mirror=$m
    break
  fi
done

if [ -z "${mirror:-}" ]; then
  echo "error: no apt mirror resolves; tried:" >&2
  for m in https://mirrors.edge.kernel.org/ubuntu \
           https://ftp.osuosl.org/pub/ubuntu \
           https://mirror.math.princeton.edu/pub/ubuntu \
           http://archive.ubuntu.com/ubuntu; do
    host=${m#*://}
    echo "  ${host%%/*}" >&2
  done
  exit 1
fi
echo "apt mirror: $mirror"

for f in /etc/apt/sources.list /etc/apt/apt-mirrors.txt /etc/apt/sources.list.d/*; do
  [ -f "$f" ] || continue
  sed -i -E \
    "s#(https?://[^ ]*ubuntu\.com/ubuntu|mirror\+file:/etc/apt/apt-mirrors\.txt)#$mirror#g" \
    "$f"
done

rm -rf /var/lib/apt/lists/*
mkdir -p /var/lib/apt/lists/partial