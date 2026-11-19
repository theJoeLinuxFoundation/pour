"""Return the real accounts in a source root, skipping daemons and system users."""
function human_users(root)
    out = NamedTuple[]
    for f in read_passwd(joinpath(root, "etc", "passwd"))
        length(f) >= 7 || continue
        name, uid, gid, home, shell = f[1], f[3], f[4], f[6], f[7]
        u = try
            parse(Int, uid)
        catch
            continue
        end
        (1000 <= u < 60000) || continue
        name == "nobody" && continue
        push!(out, (name = name, uid = u, gid = gid, home = home, shell = shell))
    end
    return out
end

"""Map a home path from inside the source root to a path on this machine."""
source_path(root, home) = joinpath(root, lstrip(home, '/'))

"""The `plan` verb: report a migration without writing anything."""
function cmd_plan(args)
    pos, _ = parse_args(args)
    if isempty(pos)
        fail("plan needs a root: pour plan /mnt/old")
        return 2
    end
    root = pos[1]
    if !is_system(root)
        fail("$root is not a Linux root: no etc/os-release")
        return 2
    end

    refuse_horizon(root) && return 3

    note("planning a migration from $root")
    ok("source: $(describe(root))")

    found = human_users(root)
    if isempty(found)
        fail("no human accounts in $root/etc/passwd")
        return 1
    end

    total_files = 0
    total_bytes = 0
    for u in found
        src = source_path(root, u.home)
        files, bytes = measure(src)
        total_files += files
        total_bytes += bytes
        groups = length(source_groups(root, u.name))
        priv = source_privileged(root, u.name) ? ", sudo" : ""
        state = is_dir(src) ? "" : " (home missing)"
        ok(string(u.name, " (", u.uid, ":", u.gid, ") ", u.home,
                 ": ", files, " files, ", human(bytes),
                 ", ", groups, " groups", priv, state))
    end

    println()
    note("total: $(length(found)) accounts, $total_files files, $(human(total_bytes))")
    note("nothing was written")
    note("next: pour run $root --users")
    return 0
end
