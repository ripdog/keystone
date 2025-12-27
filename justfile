# Keystone Justfile
# Common development commands

# Default recipe (show help)
default:
    @just --list

# Build all crates (debug)
build:
    cargo build

# Build all crates (release)
build-release:
    cargo build --release

# Run tests
test:
    cargo test --all

# Run clippy linter
clippy:
    cargo clippy --all-targets --all-features

# Format code
fmt:
    cargo fmt --all

# Check formatting
fmt-check:
    cargo fmt --all -- --check

# Run all CI checks (clippy + format + tests)
ci: fmt-check clippy test
    @echo "✅ All CI checks passed!"

# Clean build artifacts
clean:
    cargo clean

# Check compilation without building
check:
    cargo check --all

# Run daemon (requires root)
run-daemon:
    @echo "Starting daemon (requires root)..."
    sudo target/release/keystone-daemon

# Run web UI (unprivileged)
run-web:
    @echo "Starting web UI on http://localhost:8080"
    target/release/keystone-web-ui

# Build and run daemon
dev-daemon: build
    @echo "Starting daemon in dev mode (requires root)..."
    sudo target/debug/keystone-daemon

# Build and run web UI
dev-web: build
    @echo "Starting web UI in dev mode on http://localhost:8080"
    target/debug/keystone-web-ui

# Build WASM frontend (requires trunk)
build-wasm:
    cd web-ui && ~/.cargo/bin/trunk build --release

# Serve WASM frontend with hot reload (requires trunk)
serve-wasm:
    cd web-ui && ~/.cargo/bin/trunk serve

# Build everything including WASM, then run (development)
dev-full: build-wasm dev-web
    @echo "✅ Full development build ready"

# Run web UI with WASM built (requires trunk)
run-full: build-wasm run-web
    @echo "✅ Web UI running with WASM at http://localhost:8080"

# Update dependencies
update:
    cargo update

# Install development dependencies
install-dev-tools:
    cargo install cargo-watch trunk

# Check for outdated dependencies
outdated:
    cargo outdated

# Generate documentation
doc:
    cargo doc --no-deps --all

# Open documentation in browser
doc-open:
    cargo doc --no-deps --all --open

# Run security audit (requires cargo-audit)
audit:
    cargo audit

# Benchmark (if benchmarks exist)
bench:
    cargo bench

# Show dependency tree
tree:
    cargo tree

# Build core library only
build-core:
    cargo build -p keystone-core

# Build daemon only
build-daemon:
    cargo build -p keystone-daemon --release

# Build web UI only
build-web:
    cargo build -p keystone-web-ui --release

# Test core library only
test-core:
    cargo test -p keystone-core

# Test daemon only
test-daemon:
    cargo test -p keystone-daemon

# Test web UI only
test-web:
    cargo test -p keystone-web-ui

# Fix clippy warnings automatically
fix:
    cargo clippy --all-targets --all-features --fix --allow-dirty

# Prepare for release (CI + build release)
release: ci build-release
    @echo "✅ Release build ready!"
    @ls -lh target/release/keystone-*

# Quick development cycle (format + build + test)
dev: fmt build test
    @echo "✅ Development cycle complete!"

# Full clean rebuild
rebuild: clean build-release
    @echo "✅ Clean rebuild complete!"

# Vagrant VM Commands
# ====================

# Fix file permissions in /src (after rsync as root)
vagrant-fix-perms:
    vagrant ssh -c "sudo chown -R vagrant:vagrant /src"

# Start Vagrant VM (provision on first run)
vagrant-up:
    vagrant up

# SSH into Vagrant VM
vagrant-ssh:
    vagrant ssh

# Stop Vagrant VM
vagrant-halt:
    vagrant halt

# Destroy Vagrant VM
vagrant-destroy:
    vagrant destroy -f

# Rebuild Vagrant VM (destroy + up)
vagrant-rebuild:
    vagrant destroy -f
    vagrant up

# Show Vagrant VM status
vagrant-status:
    vagrant status

# Build Keystone inside Vagrant VM
vagrant-build:
    vagrant ssh -c "cd /src && cargo build --release"

# Test Keystone inside Vagrant VM
vagrant-test:
    vagrant ssh -c "cd /src && cargo test --all"

# Run Keystone daemon inside Vagrant VM (as root, background)
vagrant-run-daemon:
    vagrant ssh -c "cd /src && sudo ./target/release/keystone-daemon &"
    @echo "Daemon started in background"

# Run Keystone web-ui inside Vagrant VM (background)
vagrant-run-web:
    vagrant ssh -c "cd /src && ./target/release/keystone-web-ui &"
    @echo "Web UI started in background"
    @echo "Access at: http://192.168.56.10:8080"

# Start both services in Vagrant VM
vagrant-run-all: vagrant-run-daemon
    @sleep 2
    vagrant ssh -c "cd /src && ./target/release/keystone-web-ui &"
    @echo "✅ Services started"
    @echo "Daemon: Running as root on unix socket"
    @echo "Web UI: http://192.168.56.10:8080"

# Install Keystone binaries to /usr/local/bin in VM
vagrant-install:
    vagrant ssh -c "cd /src && sudo cp target/release/keystone-daemon /usr/local/bin/ && sudo cp target/release/keystone-web-ui /usr/local/bin/ && sudo chmod 755 /usr/local/bin/keystone-*"
    @echo "✅ Binaries installed to /usr/local/bin"

# Check if services are running
vagrant-status-services:
    vagrant ssh -c "ps aux | grep keystone | grep -v grep"

# Stop all keystone services
vagrant-stop-services:
    vagrant ssh -c "sudo pkill -f keystone-daemon; pkill -f keystone-web-ui" || true
    @echo "✅ Services stopped"

# Full integration test in Vagrant
vagrant-integration:
    @echo "🧪 Running integration test..."
    vagrant ssh -c "cd /src && cargo build --release"
    vagrant ssh -c "cd /src && sudo ./target/release/keystone-daemon &"
    @sleep 2
    vagrant ssh -c "cd /src && ./target/release/keystone-web-ui &"
    @sleep 2
    vagrant ssh -c "curl -s http://localhost:8080/health"
    @echo ""
    @echo "✅ Integration test complete"
    @echo "Access at: http://192.168.56.10:8080"
