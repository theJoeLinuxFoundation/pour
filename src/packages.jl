# SPDX-License-Identifier: BSD-3-Clause
# SPDX-FileCopyrightText: 2026 Maja Wittbrodt

"""Source package names mapped to the names dave knows.

Distro package names diverge badly: Debian says `fd-find`, Arch says `fd`,
Fedora says `fd-find` again, and one of them calls the same thing `util-linux`
in three different splits. Every entry here is a guess that a human has to
confirm, which is why `packages` only prints a command and never runs one.

Every value has to be the name of a joe recipe; a package joe does not carry
has no entry, and the test suite checks the values against joe's names.
"""
const PACKAGE_MAP = Dict(
    # editors
    "vim" => "vim",
    "vim-enhanced" => "vim",
    "nano" => "nano",

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

    # terminals and monitoring
    "htop" => "htop",
    "tmux" => "tmux",
    "lsof" => "lsof",
    "strace" => "strace",
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
    "zip" => "zip",
    "xz-utils" => "xz",
    "xz" => "xz",
    "p7zip" => "7zip",
    "tar" => "tar",

    # storage and disks
    "e2fsprogs" => "e2fsprogs",
    "btrfs-progs" => "btrfs-progs",
    "dosfstools" => "dosfstools",
    "cryptsetup" => "cryptsetup",
    "lvm2" => "lvm2",
    "parted" => "parted",
    "gparted" => "gparted",
    "smartmontools" => "smartmontools",

    # network
    "network-manager" => "networkmanager",
    "NetworkManager" => "networkmanager",
    "iwd" => "iwd",
    "wpa_supplicant" => "wpa_supplicant",
    "wireguard-tools" => "wireguard-tools",
    "openvpn" => "openvpn",
    "tcpdump" => "tcpdump",
    "iperf3" => "iperf3",
    "bind-utils" => "bind",
    "dnsutils" => "bind",
    "traceroute" => "traceroute",
    "mtr" => "mtr",
    "networkmanagerapplet" => "network-manager-applet",

    # development
    "gcc" => "gcc",
    "g++" => "gcc",
    "make" => "make",
    "cmake" => "cmake",
    "meson" => "meson",
    "ninja-build" => "ninja",
    "ninja" => "ninja",
    "pkg-config" => "pkgconf",
    "pkgconf" => "pkgconf",
    "python3" => "python",
    "python3-pip" => "python",
    "pip" => "python",
    "nodejs" => "nodejs",
    "npm" => "nodejs",
    "rustc" => "rust",
    "cargo" => "rust",
    "go" => "go",
    "docker.io" => "docker",
    "docker" => "docker",
    "podman" => "podman",
    "qemu" => "qemu-base",

    # desktop
    "firefox" => "firefox",
    "libreoffice" => "libreoffice",
    "gimp" => "gimp",
    "inkscape" => "inkscape",
    "vlc" => "vlc",
    "mpv" => "mpv",
    "ffmpeg" => "ffmpeg",
    "obs-studio" => "obs-studio",
    "keepassxc" => "keepassxc",
    "transmission-gtk" => "transmission",
    "gnome" => "gnome-shell",
    "gnome-shell" => "gnome-shell",
)

"""Where an rpm database lives in a root: sqlite, ndb or Berkeley DB, in
/usr/lib/sysimage/rpm on newer systems and /var/lib/rpm on older ones."""
const RPM_DATABASES = (
    joinpath("usr", "lib", "sysimage", "rpm", "rpmdb.sqlite"),
    joinpath("usr", "lib", "sysimage", "rpm", "Packages.db"),
    joinpath("usr", "lib", "sysimage", "rpm", "Packages"),
    joinpath("var", "lib", "rpm", "rpmdb.sqlite"),
    joinpath("var", "lib", "rpm", "Packages.db"),
    joinpath("var", "lib", "rpm", "Packages"),
)

"""Read the installed package list out of the source root, when it is readable.

`db` names the database found and `path` is where. dpkg and apk are plain
text and `readable`; an rpm database is a binary format that pour cannot read
yet, so it comes back found but not `readable`, with no names.
"""
function installed_packages(root)
    dpkg = joinpath(root, "var", "lib", "dpkg", "status")
    if is_file(dpkg)
        out = String[]
        for line in eachline(dpkg)
            startswith(line, "Package: ") && push!(out, String(line[10:end]))
        end
        return (names = out, db = "dpkg", path = dpkg, readable = true)
    end

    apk = joinpath(root, "lib", "apk", "db", "installed")
    if is_file(apk)
        out = String[]
        for line in eachline(apk)
            startswith(line, "P:") && push!(out, String(line[3:end]))
        end
        return (names = out, db = "apk", path = apk, readable = true)
    end

    for rel in RPM_DATABASES
        rpm = joinpath(root, rel)
        is_file(rpm) && return (names = String[], db = "rpm", path = rpm, readable = false)
    end

    return (names = String[], db = "unknown", path = "", readable = false)
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
    if found.db == "rpm"
        fail("found an rpm database at $(found.path), but pour cannot read rpm databases yet")
        note("where rpm is installed, list them with: rpm --root $root -qa --qf '%{NAME}\\n'")
        return 1
    end
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
