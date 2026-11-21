# SPDX-License-Identifier: BSD-3-Clause
# SPDX-FileCopyrightText: 2026 Maja Wittbrodt

"""Turn the octal escapes in /proc/mounts back into characters."""
function unescape_mount(s)
    return replace(s, "\\040" => " ", "\\011" => "\t", "\\012" => "\n", "\\134" => "\\")
end

"""Return (device, mountpoint) pairs for every /dev filesystem in /proc/mounts."""
function dev_mounts()
    out = Tuple{String,String}[]
    isfile("/proc/mounts") || return out
    for line in eachline("/proc/mounts")
        fields = split(line, ' ')
        length(fields) >= 2 || continue
        dev = String(fields[1])
        startswith(dev, "/dev/") && push!(out, (dev, unescape_mount(String(fields[2]))))
    end
    return out
end

"""Return (device, mountpoint) pairs for mounted /dev filesystems that hold a system."""
mounted_systems() = [(dev, mp) for (dev, mp) in dev_mounts() if is_system(mp)]

"""Return the /dev device mounted at `root`, or nothing when it is not a mountpoint."""
function device_of(root)
    path = try
        realpath(root)
    catch
        return nothing
    end
    dev = nothing
    for (d, mp) in dev_mounts()
        mp == path && (dev = d)   # the last mount on a path is the one in view
    end
    return dev
end

"""Print the JSON system event for a source root."""
system_event(root, device = device_of(root)) =
    event("system"; device = device, root = abspath(root), name = describe(root))

"""The `scan` verb, with output as `args` ask for; see `with_output`."""
cmd_scan(args = String[]) = with_output(scan_verb, args)

"""Report installed systems that are already mounted."""
function scan_verb()
    note("looking for installed systems under /dev mounts")
    found = mounted_systems()
    if isempty(found)
        fail("nothing found")
        note("mount the old root read-only first, for example:")
        note("  findmnt -rn -o NAME | grep ^/dev")
        note("  mount -o ro /dev/nvme0n1p2 /mnt/old")
        note("  pour plan /mnt/old")
        return 1
    end
    for (dev, mp) in found
        ok("$dev on $mp: $(describe(mp))")
        system_event(mp, dev)
    end
    note("next: pour plan <mountpoint>")
    return 0
end
