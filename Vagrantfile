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
# NOTE: We use :auto_config => false to prevent libvirt from assigning
# an IP to the host bridge, which would conflict with the router VM.
# IPs are configured in the provisioning scripts instead.
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
    # auto_config: false prevents host bridge IP conflict with router's 192.168.100.1
    router.vm.network :private_network,
      :libvirt__network_name => "keystone-lan",
      :libvirt__dhcp_enabled => false,
      :libvirt__forward_mode => "none",  # Isolated - router handles NAT
      :auto_config => false
    
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
    # auto_config: false - IP is configured in provisioning
    client.vm.network :private_network,
      :libvirt__network_name => "keystone-lan",
      :libvirt__dhcp_enabled => false,
      :libvirt__forward_mode => "none",
      :auto_config => false
    
    # Provisioning
    client.vm.provision "shell", path: "scripts/provision-client.sh"
    
    # VM resources - minimal for Alpine
    client.vm.provider "libvirt" do |libvirt|
      libvirt.memory = 256
      libvirt.cpus = 1
    end
  end
end
