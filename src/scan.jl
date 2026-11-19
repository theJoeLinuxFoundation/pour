# SPDX-License-Identifier: BSD-3-Clause
# SPDX-FileCopyrightText: 2026 Maja Wittbrodt

"""Turn the octal escapes in /proc/mounts back into characters."""
function unescape_mount(s)
    return replace(s, "\\040" => " ", "\\011" => "\t", "\\012" => "\n", "\\134" => "\\")
end

"""Return (device, mountpoint) pairs for mounted /dev filesystems that hold a system."""
function mounted_systems()
    out = Tuple{String,String}[]
    isfile("/proc/mounts") || return out
    for line in eachline("/proc/mounts")
        fields = split(line, ' ')
        length(fields) >= 2 || continue
        dev = String(fields[1])
        mp = unescape_mount(String(fields[2]))
        startswith(dev, "/dev/") || continue
        is_system(mp) && push!(out, (dev, mp))
    end
    return out
end

"""The `scan` verb: report installed systems that are already mounted."""
function cmd_scan()
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
    end
    note("next: pour plan <mountpoint>")
    return 0
end
