"""Source package names mapped to the names dave knows.

Distro package names diverge badly: Debian says `fd-find`, Arch says `fd`,
Fedora says `fd-find` again, and one of them calls the same thing `util-linux`
in three different splits. Every entry here is a guess that a human has to
confirm, which is why `packages` only prints a command and never runs one.
"""
const PACKAGE_MAP = Dict(
    # editors
    "vim" => "vim",
    "vim-enhanced" => "vim",
    "neovim" => "neovim",
    "nano" => "nano",
    "emacs" => "emacs",
    "helix" => "helix",

    # shells
    "bash" => "bash",
    "zsh" => "zsh",
    "fish" => "fish",
    "dash" => "dash",

    # version control and network basics
    "git" => "git",
    "curl" => "curl",
    "wget" => "wget",
    "rsync" => "rsync",
    "openssh-client" => "openssh",
    "openssh-server" => "openssh",
    "openssh" => "openssh",
    "gnupg" => "gnupg",
    "gnupg2" => "gnupg",
    "age" => "age",
    "pass" => "pass",

    # terminals and monitoring
    "htop" => "htop",
    "btop" => "btop",
    "tmux" => "tmux",
    "screen" => "screen",
    "lsof" => "lsof",
    "strace" => "strace",
    "ltrace" => "ltrace",
    "iotop" => "iotop",
    "ncdu" => "ncdu",
    "sysstat" => "sysstat",
    "tree" => "tree",

    # search and text
    "ripgrep" => "ripgrep",
    "fd-find" => "fd",
    "fd" => "fd",
    "fzf" => "fzf",
    "jq" => "jq",
    "less" => "less",
    "man-db" => "man-db",
    "man" => "man-db",
    "unzip" => "unzip",
    "zip" => "zip",
    "xz-utils" => "xz",
    "xz" => "xz",
    "p7zip" => "p7zip",
    "tar" => "tar",

    # storage and disks
    "e2fsprogs" => "e2fsprogs",
    "btrfs-progs" => "btrfs-progs",
    "dosfstools" => "dosfstools",
    "ntfs-3g" => "ntfs-3g",
    "cryptsetup" => "cryptsetup",
    "lvm2" => "lvm2",
    "parted" => "parted",
    "gparted" => "gparted",
    "smartmontools" => "smartmontools",
    "hdparm" => "hdparm",

    # network
    "network-manager" => "networkmanager",
    "NetworkManager" => "networkmanager",
    "iwd" => "iwd",
    "wpa_supplicant" => "wpa_supplicant",
    "wireguard-tools" => "wireguard-tools",
    "openvpn" => "openvpn",
    "nmap" => "nmap",
    "tcpdump" => "tcpdump",
    "iperf3" => "iperf",
    "bind-utils" => "bind-utils",
    "dnsutils" => "bind-utils",
    "traceroute" => "traceroute",
    "mtr" => "mtr",
    "networkmanagerapplet" => "networkmanager",

    # development
    "gcc" => "clang",
    "g++" => "clang",
    "make" => "make",
    "cmake" => "cmake",
    "meson" => "meson",
    "ninja-build" => "ninja",
    "ninja" => "ninja",
    "pkg-config" => "pkgconf",
    "pkgconf" => "pkgconf",
    "python3" => "python3",
    "python3-pip" => "python3",
    "pip" => "python3",
    "nodejs" => "nodejs",
    "npm" => "nodejs",
    "rustc" => "rust",
    "cargo" => "rust",
    "go" => "go",
    "docker.io" => "docker",
    "docker" => "docker",
    "podman" => "podman",
    "qemu" => "qemu",

    # desktop
    "firefox" => "firefox",
    "chromium" => "chromium",
    "thunderbird" => "thunderbird",
    "libreoffice" => "libreoffice",
    "gimp" => "gimp",
    "inkscape" => "inkscape",
    "blender" => "blender",
    "vlc" => "vlc",
    "mpv" => "mpv",
    "ffmpeg" => "ffmpeg",
    "obs-studio" => "obs-studio",
    "keepassxc" => "keepassxc",
    "qbittorrent" => "qbittorrent",
    "transmission-gtk" => "transmission",
    "gnome" => "gnome",
    "gnome-shell" => "gnome",
    "plasma-desktop" => "plasma",
)

"""Read the installed package list out of the source root, when it is readable."""
function installed_packages(root)
    dpkg = joinpath(root, "var", "lib", "dpkg", "status")
    if is_file(dpkg)
        out = String[]
        for line in eachline(dpkg)
            startswith(line, "Package: ") && push!(out, String(line[10:end]))
        end
        return (names = out, db = "dpkg")
    end

    apk = joinpath(root, "lib", "apk", "db", "installed")
    if is_file(apk)
        out = String[]
        for line in eachline(apk)
            startswith(line, "P:") && push!(out, String(line[3:end]))
        end
        return (names = out, db = "apk")
    end

    rpm = joinpath(root, "var", "lib", "rpm")
    if is_dir(rpm)
        out = String[]
        for entry in readdir(rpm)
            endswith(entry, ".rpm") || continue
            push!(out, String(split(entry, '-')[1]))
        end
        return (names = out, db = "rpm")
    end

    return (names = String[], db = "unknown")
end

"""The `packages` verb: map the old system's packages onto dave names."""
function cmd_packages(args)
    pos, _ = parse_args(args)
    if isempty(pos)
        fail("packages needs a root: pour packages /mnt/old")
        return 2
    end
    root = pos[1]
    if !is_system(root)
        fail("$root is not a Linux root: no etc/os-release")
        return 2
    end

    refuse_horizon(root) && return 3

    note("reading the package database in $root")
    found = installed_packages(root)
    if isempty(found.names)
        fail("no package database found, expected dpkg, apk or rpm")
        return 1
    end
    ok("$(found.db): $(length(found.names)) packages installed")

    known = String[]
    unknown = String[]
    for name in found.names
        mapped = get(PACKAGE_MAP, name, nothing)
        mapped === nothing ? push!(unknown, name) : push!(known, mapped)
    end
    sort!(known)
    unique!(known)

    println()
    if isempty(known)
        fail("nothing could be mapped, the table in packages.jl is too small")
        return 1
    end
    println("dave install " * join(known, " "))
    note("$(length(known)) mapped, $(length(unknown)) not in the table")
    note("nothing was installed, review the list first")
    return 0
end
