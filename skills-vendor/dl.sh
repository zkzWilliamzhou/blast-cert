#!/bin/bash
n=$1; repo=$2; br=${3:-main}
url="https://codeload.github.com/$repo/tar.gz/refs/heads/$br"
if timeout 90 curl -sL --fail "$url" -o "$n.tar.gz"; then
  mkdir -p "$n"; tar xzf "$n.tar.gz" -C "$n" --strip-components=1; echo "OK $n $(du -sh "$n" | cut -f1)"
else
  echo "FAIL $n $br"
fi
