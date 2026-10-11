pkgname=keystone
pkgver=0.1.0
pkgrel=1
pkgdesc="Linux router/firewall manager with split-privilege web UI"
arch=("x86_64")
url="https://github.com/example/keystone"
license=("GPL-3.0-only")
depends=("glibc" "sqlite" "nftables" "systemd" "iproute2" "iputils" "dnsmasq")
makedepends=("rust" "cargo" "trunk" "git")
options=("!strip")
install="packaging/arch/keystone.install"

build() {
  mkdir -p "${startdir}/pkg"
  chmod u+rwx,go+rx "${startdir}/pkg"
  export CARGO_TARGET_DIR="${startdir}/pkg/target"

  cd "${startdir}"
  cargo build --release

  cd "${startdir}/web-ui"
  trunk build --release
}

package() {
  install -Dm755 "${startdir}/pkg/target/release/keystone-daemon" "${pkgdir}/usr/bin/keystone-daemon"
  install -Dm755 "${startdir}/pkg/target/release/keystone-web-ui" "${pkgdir}/usr/bin/keystone-web-ui"
  install -Dm755 "${startdir}/pkg/target/release/keystonectl" "${pkgdir}/usr/bin/keystonectl"

  install -Dm644 "${startdir}/packaging/arch/keystone-daemon.service" "${pkgdir}/usr/lib/systemd/system/keystone-daemon.service"
  install -Dm644 "${startdir}/packaging/arch/keystone-web-ui.service" "${pkgdir}/usr/lib/systemd/system/keystone-web-ui.service"
  install -Dm644 "${startdir}/packaging/arch/sysusers.conf" "${pkgdir}/usr/lib/sysusers.d/keystone.conf"
  install -Dm644 "${startdir}/packaging/arch/tmpfiles.conf" "${pkgdir}/usr/lib/tmpfiles.d/keystone.conf"
  install -Dm644 "${startdir}/packaging/arch/keystone.toml" "${pkgdir}/etc/keystone/keystone.toml"

  install -Dm644 "${startdir}/README.md" "${pkgdir}/usr/share/doc/keystone/README.md"

  install -Dm644 "${startdir}/web-ui/dist/index.html" "${pkgdir}/usr/share/keystone/dist/index.html"
  install -Dm644 "${startdir}/web-ui/dist/keystone-web-ui.js" "${pkgdir}/usr/share/keystone/dist/keystone-web-ui.js"
  install -Dm644 "${startdir}/web-ui/dist/keystone-web-ui_bg.wasm" "${pkgdir}/usr/share/keystone/dist/keystone-web-ui_bg.wasm"
}
