# SPDX-License-Identifier: BSD-3-Clause
# SPDX-FileCopyrightText: 2026 Maja Wittbrodt

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
    pos, _, opts = parse_args(args)
    if isempty(pos)
        fail("plan needs a root: pour plan /mnt/old")
        return 2
    end
    root = pos[1]
    if !is_system(root)
        fail("$root is not a Linux root: no etc/os-release")
        return 2
    end
    target = target_root(opts, root)
    target === nothing && return 2

    refuse_horizon(root) && return 3

    note("planning a migration from $root")
    ok("source: $(describe(root))")
    target == "/" || ok("target: $target")
    users, _ = local_names(target)

    found = human_users(root)
    if isempty(found)
        fail("no human accounts in $root/etc/passwd")
        return 1
    end

    hashes = source_hashes(root)
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
        password = password_state(hashes, u.name)
        ok(string(u.name, " (", u.uid, ":", u.gid, ") ", u.home,
                 ": ", files, " files, ", human(bytes),
                 ", ", groups, " groups", priv, ", password ", password, state))
        carries_password(password) ||
            note("$(u.name): password $(password_reason(password)), would stay locked")
        target == "/" && continue
        dst = target_home(target, u.home)
        if u.name in users
            note("$(u.name): account exists in $target, would copy the home only")
        elseif is_dir(dst) && !isempty(readdir(dst))
            note("$(u.name): $dst already has files, would not touch it")
        else
            note("$(u.name): would go to $dst")
        end
    end

    println()
    note("total: $(length(found)) accounts, $total_files files, $(human(total_bytes))")
    note("nothing was written")
    note("next: pour run $root --users" * (target == "/" ? "" : " --target $target"))
    return 0
end
