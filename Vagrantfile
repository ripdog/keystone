# Vagrantfile
Vagrant.configure("2") do |config|
  # Use a generic Arch Linux box
  config.vm.box = "generic/arch"

  # NETWORK 1: WAN (NAT)
  # Vagrant creates this by default as the "Management network"
  # This lets you SSH in and lets the VM download Rust crates.

  # NETWORK 2: LAN (Private Network)
  # This simulates your internal home network.
  # We give it a static IP so you know where the router is.
  config.vm.network "private_network", ip: "192.168.56.10"

  # SYNCED FOLDERS
  # Disabled for now - will manually copy files
  config.vm.synced_folder ".", "/src", type: "rsync"

  # PROVISIONING (The Scriptable Part)
  # This runs the first time you do 'vagrant up'
  config.vm.provision "shell", path: "scripts/provision.sh"

  # Tweak VM resources
  config.vm.provider "libvirt" do |vb|
    vb.memory = "2048"
    vb.cpus = 2
  end
end