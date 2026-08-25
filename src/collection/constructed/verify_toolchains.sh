#!/bin/bash
# verify_toolchains.sh - Confirm all three compilers produce a Windows binary
# before the grid is built.
#
# Nine hundred failed builds discovered one at a time is a bad way to find
# out that a toolchain is missing, so this builds one variant with each and
# checks the result is a PE executable.
set -u
ok=0; fail=0

echo "=== mingw C ==="
if x86_64-w64-mingw32-gcc -O2 -DSHAPE=4 -DLIMIT=200 -DORDER=1 \
     -o /tmp/t_c.exe c/hardneg_matrix.c 2>/tmp/e_c.txt; then
  file /tmp/t_c.exe | head -1; ok=$((ok+1))
else
  echo "FAILED:"; head -5 /tmp/e_c.txt; fail=$((fail+1))
fi

echo
echo "=== Go ==="
if command -v go >/dev/null 2>&1; then
  if (cd go && GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build \
        -ldflags "-X main.shape=4 -X main.limit=200" \
        -o /tmp/t_go.exe . 2>/tmp/e_go.txt); then
    file /tmp/t_go.exe | head -1; ok=$((ok+1))
  else
    echo "FAILED:"; head -20 /tmp/e_go.txt; fail=$((fail+1))
  fi
else
  echo "go not installed:  sudo apt-get install -y golang-go"; fail=$((fail+1))
fi

echo
echo "=== Rust ==="
if command -v cargo >/dev/null 2>&1; then
  if (cd rust && HN_SHAPE=4 HN_LIMIT=200 cargo build --release \
        --target x86_64-pc-windows-gnu 2>/tmp/e_rs.txt); then
    file rust/target/x86_64-pc-windows-gnu/release/hardneg.exe | head -1
    ok=$((ok+1))
  else
    echo "FAILED:"; tail -25 /tmp/e_rs.txt; fail=$((fail+1))
  fi
else
  echo "cargo not installed:"
  echo "  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y"
  echo "  source \$HOME/.cargo/env"
  echo "  rustup target add x86_64-pc-windows-gnu"
  fail=$((fail+1))
fi

echo
echo "빌드 성공 $ok, 실패 $fail"
[ $fail -eq 0 ] && echo "세 툴체인 모두 준비됨 — build_shape_grid.py 진행 가능"
