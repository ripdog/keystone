# Vagrantfile - Keystone Multi-VM Test Environment
#
# Network Architecture:
#
#   Host (upstream internet)
#     │
#     │ NAT (vagrant-libvirt management network)
#     │
#   ┌─┴───────────────┐
#   │  Router (Arch)  │ eth0: management (SSH + internet)
#   │   Keystone      │ eth1: LAN (192.168.100.1)
#   └────────┬────────┘
#            │
#            │ LAN network (192.168.100.0/24)
#            │
#   ┌────────┴────────┐
#   │  Client (Alpine)│ eth0: management (for vagrant SSH)
#   │  (test target)  │ eth1: LAN (DHCP from router -> 192.168.100.x)
#   └─────────────────┘
#
# Testing approach:
# - Client has management network for Vagrant SSH access
# - Client's LAN interface (eth1) gets DHCP from router
# - All test traffic goes through eth1 -> router -> internet
# - Firewall rules tested on LAN traffic, not management traffic
#

Vagrant.configure("2") do |config|
  
  # ============================================================
  # ROUTER VM - Arch Linux running Keystone
  # ============================================================
  config.vm.define "router", primary: true do |router|
    router.vm.box = "generic/arch"
    router.vm.hostname = "keystone-router"
    
    # Synced folder for source code
    router.vm.synced_folder ".", "/src", type: "rsync"
    
    # NETWORK 1: Management (NAT) - automatically created by vagrant-libvirt
    # This is for SSH access and internet connectivity (package downloads)
    
    # NETWORK 2: LAN (private network for client VMs)
    # Router acts as gateway for this network
    router.vm.network :private_network,
      :ip => "192.168.100.1",
      :libvirt__network_name => "keystone-lan",
      :libvirt__netmask => "255.255.255.0",
      :libvirt__dhcp_enabled => false,
      :libvirt__forward_mode => "none"  # Isolated - router handles NAT
    
    # Provisioning
    router.vm.provision "shell", path: "scripts/provision-router.sh"
    
    # VM resources
    router.vm.provider "libvirt" do |libvirt|
      libvirt.memory = 2048
      libvirt.cpus = 2
    end
  end
  
  # ============================================================
  # CLIENT VM - Alpine Linux (lightweight test target)
  # ============================================================
  config.vm.define "client" do |client|
    client.vm.box = "generic/alpine318"
    client.vm.hostname = "test-client"
    
    # NETWORK: LAN (same network as router's eth1)
    # Client will get DHCP from router's dnsmasq on this interface
    # We set a static IP here for Vagrant, but the client will use DHCP in practice
    client.vm.network :private_network,
      :ip => "192.168.100.10",
      :libvirt__network_name => "keystone-lan",
      :libvirt__netmask => "255.255.255.0",
      :libvirt__dhcp_enabled => false,
      :libvirt__forward_mode => "none"
    
    # Provisioning
    client.vm.provision "shell", path: "scripts/provision-client.sh"
    
    # VM resources - minimal for Alpine
    client.vm.provider "libvirt" do |libvirt|
      libvirt.memory = 256
      libvirt.cpus = 1
    end
  end
end
