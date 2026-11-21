# SPDX-License-Identifier: BSD-3-Clause
# SPDX-FileCopyrightText: 2026 Maja Wittbrodt

"""Change an owner without following symlinks."""
lchown(path, uid, gid) = ccall(:lchown, Cint, (Cstring, Cuint, Cuint), path, uid, gid)

"""Copy a tree keeping modes, owners and symlinks exactly as they are."""
function copy_tree(src, dst; dry = false)
    files = 0
    links = 0
    bytes = 0
    isdir(src) || return (files = files, links = links, bytes = bytes)
    for (dir, _, entries) in walkdir(src; follow_symlinks = false)
        rel = relpath(dir, src)
        target_dir = rel == "." ? dst : joinpath(dst, rel)
        dry || mkpath(target_dir)
        for entry in entries
            s = joinpath(dir, entry)
            d = joinpath(target_dir, entry)
            st = safe_lstat(s)
            st === nothing && continue
            if islink(s)
                dry || (rm(d; force = true); symlink(readlink(s), d))
                links += 1
                continue
            end
            if !isfile(s)
                continue
            end
            if dry
                files += 1
                bytes += st.size
                continue
            end
            cp(s, d; force = true)
            chmod(d, st.mode & 0o7777)
            lchown(d, st.uid, st.gid)
            files += 1
            bytes += st.size
        end
        if !dry
            st = safe_lstat(dir)
            if st !== nothing
                chmod(target_dir, st.mode & 0o7777)
                lchown(target_dir, st.uid, st.gid)
            end
        end
    end
    return (files = files, links = links, bytes = bytes)
end

"""Compare hashes for a sample of copied files against their sources."""
function verify_sample(src, dst; limit = 200)
    checked = 0
    bad = 0
    for (dir, _, entries) in walkdir(src; follow_symlinks = false)
        for entry in entries
            checked >= limit && return (checked = checked, bad = bad)
            s = joinpath(dir, entry)
            (islink(s) || !isfile(s)) && continue
            st = safe_lstat(s)
            st === nothing && continue
            size = st.size
            size > 8 * 1024 * 1024 && continue
            d = joinpath(dst, relpath(s, src))
            isfile(d) || (bad += 1; continue)
            checked += 1
            a = open(sha256, s)
            b = open(sha256, d)
            a == b || (bad += 1)
        end
    end
    return (checked = checked, bad = bad)
end

"""Return the names in the passwd and group files under `target`, this machine by default."""
function local_names(target = "/")
    users = Set(f[1] for f in read_passwd(joinpath(target, "etc", "passwd")) if length(f) >= 7)
    groups = Set(f[1] for f in read_passwd(joinpath(target, "etc", "group")) if length(f) >= 3)
    return users, groups
end

"""Return the supplemental groups a user belongs to in the source root."""
function source_groups(root, username)
    out = Tuple{String,Int}[]
    for f in read_passwd(joinpath(root, "etc", "group"))
        length(f) >= 4 || continue
        name, gid, members = f[1], f[3], f[4]
        g = try
            parse(Int, gid)
        catch
            continue
        end
        for m in split(members, ',')
            strip(m) == username && push!(out, (name, g))
        end
    end
    return out
end

"""Return true when the source gave this user administrative rights."""
function source_privileged(root, username)
    for f in read_passwd(joinpath(root, "etc", "group"))
        length(f) >= 4 || continue
        f[1] in ("wheel", "sudo", "admin") || continue
        any(m -> strip(m) == username, split(f[4], ',')) && return true
    end
    return false
end

"""Return true when some group under `target`, this machine by default, already holds this gid."""
function gid_taken(gid, target = "/")
    return any(read_passwd(joinpath(target, "etc", "group"))) do f
        length(f) >= 3 && f[3] == string(gid)
    end
end

"""Build a shadow command line that edits the passwd and group files under `target`.

On this machine's own root it is the plain tool. Anywhere else the tool gets
`--prefix target`, which shadow's useradd, groupadd, usermod and chpasswd all
take, so nothing on the running system changes. Names go after `--` so that
one starting with a dash is never read as an option.
"""
function shadow_cmd(tool, target, args...)
    prefix = target == "/" ? String[] : ["--prefix", target]
    return Cmd([tool; prefix; String[string(a) for a in args]])
end

"""Run an external command, with `input` on its stdin when given."""
function run_cmd(cmd, input = nothing)
    run(input === nothing ? cmd : pipeline(cmd; stdin = IOBuffer(input)))
    return true
end

"""Map a home path from the source's passwd to where it lands under `target`."""
target_home(target, home) = joinpath(target, lstrip(home, '/'))

"""The `run` verb: create accounts and copy their homes.

`runner` executes each external command; tests pass one that records them.
"""
function cmd_run(args; runner = run_cmd)
    pos, flags, opts = parse_args(args)
    if isempty(pos)
        fail("run needs a root: pour run /mnt/old --users")
        return 2
    end
    root = pos[1]
    if !is_system(root)
        fail("$root is not a Linux root: no etc/os-release")
        return 2
    end
    target = target_root(opts, root)
    target === nothing && return 2
    dry = "--dry-run" in flags
    verify = !("--no-verify" in flags)
    if !("--users" in flags)
        note("nothing selected; pass --users to migrate accounts and homes")
        return 2
    end

    refuse_horizon(root) && return 3

    note(dry ? "dry run, nothing will be written" : "migrating from $root")
    target == "/" || note("writing accounts and homes into $target")
    users, groups = local_names(target)
    failures = 0

    for u in human_users(root)
        src = source_path(root, u.home)
        dst = target_home(target, u.home)

        if !isdir(src)
            fail("$(u.name): home missing in source, $src")
            failures += 1
            continue
        end
        if isdir(dst) && !isempty(readdir(dst))
            fail("$(u.name): $dst already has files, not touching it")
            failures += 1
            continue
        end

        if !(u.name in users)
            if !gid_taken(u.gid, target) && !(u.name in groups)
                if dry
                    ok("$(u.name): would create group $(u.name) ($(u.gid))")
                else
                    runner(shadow_cmd("groupadd", target, "-g", u.gid, "--", u.name))
                    ok("$(u.name): created group $(u.name) ($(u.gid))")
                end
            end
            if dry
                ok("$(u.name): would create user $(u.uid)")
            else
                runner(shadow_cmd("useradd", target, "-M", "-u", u.uid, "-g", u.gid,
                                  "-d", u.home, "-s", u.shell, "--", u.name))
                ok("$(u.name): created user $(u.uid)")
            end
        else
            note("$(u.name): account exists here, copying home only")
        end

        for (gname, gid) in source_groups(root, u.name)
            gname in ("wheel", "sudo", "admin") && continue
            if !(gname in groups) && !gid_taken(gid, target)
                if dry
                    ok("$(u.name): would create group $gname ($gid)")
                else
                    runner(shadow_cmd("groupadd", target, "-g", gid, "--", gname))
                    ok("$(u.name): created group $gname ($gid)")
                end
            end
            if dry
                ok("$(u.name): would join group $gname")
            else
                runner(shadow_cmd("usermod", target, "-aG", gname, "--", u.name))
                ok("$(u.name): joined group $gname")
            end
        end

        stats = copy_tree(src, dst; dry = dry)
        ok(string(u.name, ": ", stats.files, " files, ", stats.links,
                 " symlinks, ", human(stats.bytes), dry ? " (planned)" : ""))

        if verify && !dry
            v = verify_sample(src, dst)
            if v.bad == 0
                ok("$(u.name): verified $(v.checked) files")
            else
                fail("$(u.name): $(v.bad) of $(v.checked) files differ")
                failures += 1
            end
        end
    end

    for u in human_users(root)
        source_privileged(root, u.name) || continue
        note("$(u.name): had sudo in the source; joe uses doas")
        note("  add to $(joinpath(target, "etc", "doas.conf")): permit persist :wheel")
        note("  then: " * join(shadow_cmd("usermod", target, "-aG", "wheel", u.name).exec, " "))
    end

    println()
    if failures == 0
        note("done, no failures")
        return 0
    end
    fail("$failures account(s) had problems")
    return 1
end
