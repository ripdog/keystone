pkgname=keystone-router
pkgver=$(awk '/^\[workspace\.package\]$/ { in_package = 1; next } /^\[/ { in_package = 0 } in_package && /^version = / { gsub(/"/, "", $3); print $3; exit }' Cargo.toml)
pkgrel=1
pkgdesc="Linux router/firewall manager with split-privilege web UI"
arch=("x86_64")
url="https://github.com/ripdog/keystone"
license=("GPL-3.0-only")
depends=("glibc" "sqlite" "nftables" "conntrack-tools" "systemd" "iproute2" "iputils" "dnsmasq" "hwdata")
optdepends=('miniupnpd-nft: UPnP IGD and NAT-PMP port mapping (AUR; the extra/miniupnpd build uses iptables and is unsupported)'
            'blocky-bin: DNS ad-blocking and encrypted upstream DNS (AUR)')
makedepends=("rust" "cargo" "trunk" "git")
conflicts=('keystone') # the extra repo's assembler framework shares the old name
# Do not inherit host-specific -march=native/-O3/LTO flags. C dependencies
# (including cryptographic RNG implementations) control their own optimisation.
options=("!strip" "!buildflags" "!lto")
install="packaging/arch/keystone.install"

build() {
  # In addition to makepkg options, clear explicitly inherited compiler flags.
  # This keeps the package portable across x86_64 USB target machines and lets
  # C dependencies request -O0 for files that cannot tolerate optimisations.
  unset CFLAGS CXXFLAGS CPPFLAGS LDFLAGS RUSTFLAGS CARGO_ENCODED_RUSTFLAGS
  unset CFLAGS_x86_64_unknown_linux_gnu CXXFLAGS_x86_64_unknown_linux_gnu
  unset CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS

  mkdir -p "${startdir}/pkg"
  chmod u+rwx,go+rx "${startdir}/pkg"
  export CARGO_TARGET_DIR="${startdir}/pkg/target"

  cd "${startdir}"
  cargo build --release --locked

  cd "${startdir}/web-ui"
  trunk build --release --locked
}

package() {
  install -Dm755 "${startdir}/pkg/target/release/keystone-daemon" "${pkgdir}/usr/bin/keystone-daemon"
  install -Dm755 "${startdir}/pkg/target/release/keystone-web-ui" "${pkgdir}/usr/bin/keystone-web-ui"
  install -Dm755 "${startdir}/pkg/target/release/keystonectl" "${pkgdir}/usr/bin/keystonectl"

  install -Dm644 "${startdir}/packaging/arch/keystone-daemon.service" "${pkgdir}/usr/lib/systemd/system/keystone-daemon.service"
  install -Dm644 "${startdir}/packaging/arch/keystone-web-ui.service" "${pkgdir}/usr/lib/systemd/system/keystone-web-ui.service"
  install -Dm644 "${startdir}/packaging/arch/keystone-blocky.service" "${pkgdir}/usr/lib/systemd/system/keystone-blocky.service"
  install -Dm644 "${startdir}/packaging/arch/miniupnpd.service.d/keystone.conf" "${pkgdir}/usr/lib/systemd/system/miniupnpd.service.d/keystone.conf"
  install -Dm644 "${startdir}/packaging/arch/systemd-networkd.service.d/keystone.conf" "${pkgdir}/usr/lib/systemd/system/systemd-networkd.service.d/keystone.conf"
  install -Dm644 "${startdir}/packaging/arch/sysusers.conf" "${pkgdir}/usr/lib/sysusers.d/keystone.conf"
  install -Dm644 "${startdir}/packaging/arch/tmpfiles.conf" "${pkgdir}/usr/lib/tmpfiles.d/keystone.conf"
  install -Dm644 "${startdir}/packaging/arch/keystone-modules.conf" "${pkgdir}/usr/lib/modules-load.d/keystone.conf"
  install -Dm644 "${startdir}/packaging/arch/keystone.toml" "${pkgdir}/etc/keystone/keystone.toml"

  install -Dm644 "${startdir}/packaging/arch/keystone-banner.sh" "${pkgdir}/etc/profile.d/keystone-banner.sh"
  install -Dm644 "${startdir}/packaging/arch/keystone-banner.fish" "${pkgdir}/usr/share/fish/vendor_conf.d/keystone-banner.fish"

  # Shell completions come from the CLI definition, so they cannot drift.
  local ctl="${startdir}/pkg/target/release/keystonectl"
  "${ctl}" completions fish | install -Dm644 /dev/stdin "${pkgdir}/usr/share/fish/vendor_completions.d/keystonectl.fish"
  "${ctl}" completions bash | install -Dm644 /dev/stdin "${pkgdir}/usr/share/bash-completion/completions/keystonectl"
  "${ctl}" completions zsh | install -Dm644 /dev/stdin "${pkgdir}/usr/share/zsh/site-functions/_keystonectl"

  install -Dm644 "${startdir}/README.md" "${pkgdir}/usr/share/doc/keystone/README.md"

  install -Dm644 "${startdir}/web-ui/dist/index.html" "${pkgdir}/usr/share/keystone/dist/index.html"
  install -Dm644 "${startdir}/web-ui/dist/keystone-web-ui.js" "${pkgdir}/usr/share/keystone/dist/keystone-web-ui.js"
  install -Dm644 "${startdir}/web-ui/dist/keystone-web-ui_bg.wasm" "${pkgdir}/usr/share/keystone/dist/keystone-web-ui_bg.wasm"
  install -Dm644 "${startdir}/web-ui/dist/tailwind.css" "${pkgdir}/usr/share/keystone/dist/tailwind.css"
  install -Dm644 "${startdir}/web-ui/dist/favicon.svg" "${pkgdir}/usr/share/keystone/dist/favicon.svg"
}
