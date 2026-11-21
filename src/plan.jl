# SPDX-License-Identifier: BSD-3-Clause
# SPDX-FileCopyrightText: 2026 Maja Wittbrodt

"""Return the real accounts in a source root, skipping daemons and system users."""
function human_users(root)
    out = NamedTuple[]
    for f in read_passwd(joinpath(root, "etc", "passwd"))
        length(f) >= 7 || continue
        name, home, shell = f[1], f[6], f[7]
        u = tryparse(Int, f[3])
        g = tryparse(Int, f[4])
        (u === nothing || g === nothing) && continue
        (1000 <= u < 60000) || continue
        name == "nobody" && continue
        push!(out, (name = name, uid = u, gid = g, home = home, shell = shell))
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

    found = human_users(root)
    if isempty(found)
        fail("no human accounts in $root/etc/passwd")
        return 1
    end

    ids = taken_ids(target)
    hashes = source_hashes(root)
    total_files = 0
    total_bytes = 0
    planned = 0
    for u in found
        c = check_account(u, root, target, ids)
        if isempty(c.src)
            fail("$(u.name): $(c.problem), would skip")
            continue
        end
        files, bytes = measure(c.src)
        groups = length(source_groups(root, u.name))
        priv = source_privileged(root, u.name) ? ", sudo" : ""
        password = password_state(hashes, u.name)
        ok(string(u.name, " (", u.uid, ":", u.gid, ") ", c.home,
                 ": ", files, " files, ", human(bytes),
                 ", ", groups, " groups", priv, ", password ", password))
        if c.problem !== nothing
            fail("$(u.name): $(c.problem), would skip")
            continue
        end
        carries_password(password) ||
            note("$(u.name): password $(password_reason(password)), would stay locked")
        target == "/" || note("$(u.name): would go to $(c.dst)")
        # Later accounts see this one's name, uid and group as taken, as run would.
        haskey(ids.groups, c.group) || take_group!(ids, c.group, u.gid)
        take_user!(ids, u.name, u.uid)
        planned += 1
        total_files += files
        total_bytes += bytes
    end

    println()
    note("total: $planned accounts, $total_files files, $(human(total_bytes))")
    skipped = length(found) - planned
    skipped > 0 && note("$skipped account(s) would be skipped")
    note("nothing was written")
    note("next: pour run $root --users" * (target == "/" ? "" : " --target $target"))
    return 0
end
