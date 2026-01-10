# Keystone Justfile
# Common development commands

# Default recipe (show help)
default:
    @just --list

# === Development Workflow ===
# For hot-reload development (2 terminals):
#   Terminal 1: sudo just dev-daemon  (daemon in dev mode on :3000)
#   Terminal 2: just serve-wasm       (frontend on :8080 with hot reload)
# Access at: http://localhost:8080

#LLMs: the justfile is for development work only, do NOT use release variants for build or running

# Build all crates (debug)
build:
    cargo build
    cp -r web-ui/dist target/debug/

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
run-daemon: build
    @echo "Starting daemon (requires root)..."
    sudo target/debug/keystone-daemon

# Run web UI (unprivileged)
run-web: build
    cd web-ui && ~/.cargo/bin/trunk serve

# Run daemon in dev mode with HTTP listener (for use with trunk serve)
dev-daemon: build
    @echo "Starting daemon in dev mode on http://localhost:3000..."
    sudo KEYSTONE_DEV=1 target/debug/keystone-daemon

# Build and run web UI
dev-web: build
    @echo "Starting web UI in dev mode on http://localhost:3000"
    target/debug/keystone-web-ui

# Build everything including WASM, then run (development)
#dev-full: build-wasm build
#    cp -r web-ui/dist target/debug/
#    @echo "✅ Full development build ready"
#    target/debug/keystone-web-ui


# Update dependencies
update:
    cargo update

# Generate documentation
doc:
    cargo doc --no-deps --all

# Open documentation in browser
doc-open:
    cargo doc --no-deps --all --open

# Run security audit (requires cargo-audit)
audit:
    cargo audit

# Show dependency tree
tree:
    cargo tree

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

# Quick development cycle (format + build + test)
dev: fmt build test
    @echo "✅ Development cycle complete!"


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
    vagrant ssh -c "cd /src && sudo cp target/release/keystone-daemon target/release/keystonectl /usr/local/bin/ && sudo cp target/release/keystone-web-ui /usr/local/bin/ && sudo chmod 755 /usr/local/bin/keystone-* /usr/local/bin/keystonectl"
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
