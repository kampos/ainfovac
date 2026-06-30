#!/bin/bash
set -euo pipefail

install_dir=${1:?missing install directory}
project_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
deb="$project_dir/snap/local/ainfovac.deb"

if [[ ! -f "$deb" ]]; then
  echo "ERROR: missing working Debian package: $deb" >&2
  exit 1
fi

actual_deb_sha256=$(sha256sum "$deb" | awk '{print $1}')

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

dpkg-deb -x "$deb" "$tmp/deb"

binary="$tmp/deb/usr/bin/ainfovac"
if [[ ! -f "$binary" ]]; then
  echo "ERROR: the .deb does not contain usr/bin/ainfovac" >&2
  exit 3
fi

expected_binary_sha256=$(sha256sum "$binary" | awk '{print $1}')
expected_binary_size=$(stat -Lc '%s' "$binary")

# Install the exact payload from the known-working .deb. Do not compile or
# alter the Gambas project source in any way.
mkdir -p "$install_dir"
cp -a "$tmp/deb/." "$install_dir/"

# Snap-only compatibility layer and launcher.
mkdir -p \
  "$install_dir/usr/lib/ainfovac" \
  "$install_dir/usr/share/applications" \
  "$install_dir/bin"

gcc -shared -fPIC -O2 \
  "$project_dir/snap/gambas-snap-compat.c" \
  -o "$install_dir/usr/lib/ainfovac/libgambas-snap-compat.so" \
  -ldl

install -m 0755 "$project_dir/snap/ainfovac-launch" \
  "$install_dir/bin/ainfovac-launch"
install -m 0644 "$project_dir/snap/ainfovac.desktop" \
  "$install_dir/usr/share/applications/ainfovac.desktop"

# The application expects both names in different code paths.
if [[ ! -e "$install_dir/usr/share/ainfovac/ainfogra_local.html" ]]; then
  cp -a "$install_dir/usr/share/ainfovac/ainfogra_local.txt" \
    "$install_dir/usr/share/ainfovac/ainfogra_local.html"
fi

# Final guard: ensure the executable inside the snap remains byte-identical to
# the one in the working Debian package.
installed_sha256=$(sha256sum "$install_dir/usr/bin/ainfovac" | awk '{print $1}')
installed_size=$(stat -Lc '%s' "$install_dir/usr/bin/ainfovac")
if [[ "$installed_sha256" != "$expected_binary_sha256" || \
      "$installed_size" != "$expected_binary_size" ]]; then
  echo "ERROR: AinfoVac binary changed while building the snap." >&2
  exit 5
fi

printf '%s  usr/bin/ainfovac\n' "$installed_sha256" \
  > "$install_dir/usr/share/ainfovac/SNAP_BINARY_SHA256"
printf '%s  snap/local/ainfovac.deb\n' "$actual_deb_sha256" \
  > "$install_dir/usr/share/ainfovac/SNAP_DEB_SHA256"

echo "Installed exact working .deb executable: $installed_size bytes"
echo "SHA-256: $installed_sha256"
