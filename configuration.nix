# Secure NixOS configuration with reasonable security measures

{ config, pkgs, ... }:

{
  imports =
    [ # Include the results of the hardware scan.
      ./hardware-configuration.nix
    ];

  # Bootloader with Secure Boot (if applicable)
  boot.loader.grub.enable = true;
  boot.loader.grub.device = "/dev/sda";
  boot.loader.grub.useOSProber = false; # Prevents boot-time enumeration of foreign OSes
  boot.loader.grub.enableCryptodisk = true;

  # Secure keyfile setup for encrypted LUKS partition
  boot.initrd.secrets = {
    "/boot/crypto_keyfile.bin" = null;
  };
  boot.initrd.luks.devices."luks-UUID".keyFile = "path/to/keyfile.bin";

  networking.hostName = "hostname"; # Define your hostname.

  # Enable NetworkManager for Wi-Fi
  networking.networkmanager.enable = true;

  # Set your time zone.
  time.timeZone = "Europe/Amsterdam";

  # Define Localization settings.
  i18n.defaultLocale = "en_US.UTF-8";
  i18n.extraLocaleSettings = {
    LC_ADDRESS = "nl_NL.UTF-8";
    LC_IDENTIFICATION = "nl_NL.UTF-8";
    LC_MEASUREMENT = "nl_NL.UTF-8";
    LC_MONETARY = "nl_NL.UTF-8";
    LC_NAME = "nl_NL.UTF-8";
    LC_NUMERIC = "nl_NL.UTF-8";
    LC_PAPER = "nl_NL.UTF-8";
    LC_TELEPHONE = "nl_NL.UTF-8";
    LC_TIME = "nl_NL.UTF-8";
  };

  # Hardened kernel
  boot.kernelPackages = pkgs.linuxPackages_hardened;
  boot.kernel.sysctl = {
    "kernel.kptr_restrict" = 2;
    "kernel.randomize_va_space" = 2;
    "kernel.unprivileged_bpf_disabled" = 1;
    "net.ipv4.conf.all.rp_filter" = 1;
    "net.ipv4.icmp_echo_ignore_all" = 1;
    "net.ipv4.tcp_syncookies" = 1;
    "net.ipv4.conf.all.accept_redirects" = 0;
    "net.ipv4.conf.default.accept_redirects" = 0;
    "net.ipv6.conf.all.accept_redirects" = 0;
    "net.ipv6.conf.default.accept_redirects" = 0;
    "net.ipv4.conf.all.send_redirects" = 0;
  };

  # Enable X11 and GNOME Desktop Environment
  services.xserver.enable = true;
  services.xserver.displayManager.gdm.enable = true;
  services.xserver.desktopManager.gnome.enable = true;

  # Secure keymap in X11
  services.xserver.xkb = {
    layout = "us";
    variant = "euro";
  };

  # Enable firewall with strict settings
  networking.firewall.enable = true;
  networking.firewall.allowedTCPPorts = [ 22 ]; # Only allow SSH
  networking.firewall.allowedUDPPorts = [];
  networking.firewall.rejectPackets = true;
  networking.firewall.logRefusedConnections = true;

    # Secure OpenSSH settings
    services.openssh = {
      enable = true;
      passwordAuthentication = false;
      permitRootLogin = "no";
      extraConfig = ''
        # Modern cryptographic algorithms only
        KexAlgorithms curve25519-sha256@libssh.org
        Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
        MACs hmac-sha2-512-etm@openssh.com
      
        # Connection restrictions
        AllowTcpForwarding no
        X11Forwarding no
        PermitEmptyPasswords no
        AllowAgentForwarding no
      '';
    };

  # Harden sudo
  security.sudo.extraConfig = ''
    Defaults timestamp_timeout=0
    Defaults passwd_timeout=1
    Defaults use_pty
    Defaults log_input,log_output
    Defaults logfile=/var/log/sudo.log
  '';

  # Enable AppArmor
  boot.kernelParams = [ "apparmor=1" "security=apparmor" ];
  security.apparmor.enable = true;

  # Enable automatic updates
  system.autoUpgrade.enable = true;
  system.autoUpgrade.allowReboot = true;

  # Disk encryption integrity
  boot.initrd.kernelModules = [ "dm-integrity" "dm-verity" ];

  # Enable ClamAV for malware scanning
  services.clamav.daemon.enable = true;
  services.clamav.updater.enable = true;

  # Enable fail2ban for brute-force protection
  services.fail2ban.enable = true;

  # Enable printing
  services.printing.enable = true;

  # Enable sound with PipeWire
  hardware.pulseaudio.enable = false;
  security.rtkit.enable = true;
  services.pipewire = {
    enable = true;
    alsa.enable = true;
    alsa.support32Bit = true;
    pulse.enable = true;
  };

  # Define user
  users.users.void = {
    isNormalUser = true;
    description = "username"; # Define username
    extraGroups = [ "networkmanager" "wheel" ];
    shell = pkgs.zsh;
    packages = with pkgs; [
      # Add user-specific packages here
    ];
  };

  programs.zsh = {
    enable = true;
    autosuggestions.enable = true;
    syntaxHighlighting.enable = true;
    ohMyZsh = {
      enable = true;
      plugins = [ "git" "sudo" "docker" ];
      theme = "robbyrussell"; # Optional: Set your favorite theme
    };
  };

  # Install Firefox
  programs.firefox.enable = true;

  # Allow unfree packages
  nixpkgs.config.allowUnfree = true;

  # System-wide packages
  environment.systemPackages = with pkgs; [
    zsh
    vim
    wget
    neofetch
    audit  # Kernel auditing tool 
    git
  ];

  # System state version
  system.stateVersion = "24.11";

}
