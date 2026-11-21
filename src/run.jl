# SPDX-License-Identifier: BSD-3-Clause
# SPDX-FileCopyrightText: 2026 Maja Wittbrodt

"""Change an owner without following symlinks."""
lchown(path, uid, gid) = ccall(:lchown, Cint, (Cstring, Cuint, Cuint), path, uid, gid)

"""Return the owner a copied entry gets, and whether that differs from its own.

Without an `owner` every entry keeps its uid and gid. With one, an entry that
belongs to any other uid, such as root, goes to the account's uid and gid.
"""
function new_owner(uid, gid, owner)
    (owner === nothing || uid == owner.uid) && return (uid, gid, false)
    return (owner.uid, owner.gid, true)
end

"""Copy a tree keeping modes and symlinks, but no setuid or setgid file.

Files lose their setuid and setgid bits; directories keep theirs, which only
steer the group of new files. With an `owner`, entries owned by another uid
are handed to it, see `new_owner`. The result counts files, symlinks and
bytes, the files that were `stripped` and the entries that were `chowned`.
"""
function copy_tree(src, dst; dry = false, owner = nothing)
    files = 0
    links = 0
    bytes = 0
    stripped = 0
    chowned = 0
    stats() = (files = files, links = links, bytes = bytes, stripped = stripped, chowned = chowned)
    isdir(src) || return stats()
    for (dir, _, entries) in walkdir(src; follow_symlinks = false)
        rel = relpath(dir, src)
        target_dir = rel == "." ? dst : joinpath(dst, rel)
        !dry && islink(target_dir) && error("$target_dir is a symlink, not writing through it")
        dry || mkpath(target_dir)
        for entry in entries
            s = joinpath(dir, entry)
            d = joinpath(target_dir, entry)
            st = safe_lstat(s)
            st === nothing && continue
            islink(s) || isfile(s) || continue
            uid, gid, moved = new_owner(st.uid, st.gid, owner)
            chowned += moved
            if islink(s)
                dry || (rm(d; force = true); symlink(readlink(s), d); lchown(d, uid, gid))
                links += 1
                continue
            end
            mode = st.mode & 0o7777
            stripped += (mode & 0o6000) != 0
            files += 1
            bytes += st.size
            dry && continue
            cp(s, d; force = true)
            # chown first: it may clear set-id bits itself, chmod then sets the mode exactly.
            lchown(d, uid, gid)
            chmod(d, mode & 0o1777)
        end
        st = safe_lstat(dir)
        if st !== nothing
            uid, gid, moved = new_owner(st.uid, st.gid, owner)
            chowned += moved
            if !dry
                lchown(target_dir, uid, gid)
                chmod(target_dir, st.mode & 0o7777)
            end
        end
    end
    return stats()
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

"""crypt(3) prefixes and the scheme each one names."""
const HASH_SCHEMES = (
    "\$y\$" => "yescrypt",
    "\$gy\$" => "gost-yescrypt",
    "\$7\$" => "scrypt",
    "\$2b\$" => "bcrypt",
    "\$2a\$" => "bcrypt",
    "\$2y\$" => "bcrypt",
    "\$6\$" => "sha512crypt",
    "\$5\$" => "sha256crypt",
    "\$1\$" => "md5crypt",
    "\$sha1\$" => "sha1crypt",
    "\$md5" => "sunmd5",
)

"""Return each account's password hash from the source's etc/shadow, or nothing if unreadable."""
function source_hashes(root)
    path = joinpath(root, "etc", "shadow")
    out = Dict{String,String}()
    isfile(path) || return out
    entries = try
        read_passwd(path)
    catch
        return nothing
    end
    for f in entries
        length(f) >= 2 && (out[f[1]] = f[2])
    end
    return out
end

"""Name the scheme of a crypt(3) hash, or say why there is nothing to carry.

`!` and `*` hashes are "locked" and an empty one is "empty"; otherwise the
result is the scheme, such as "yescrypt" for `\$y\$` or "sha512crypt" for
`\$6\$`, or "unknown".
"""
function hash_scheme(hash)
    isempty(hash) && return "empty"
    (startswith(hash, '!') || startswith(hash, '*')) && return "locked"
    for (prefix, name) in HASH_SCHEMES
        startswith(hash, prefix) && return name
    end
    startswith(hash, '_') && length(hash) == 20 && return "bsdicrypt"
    length(hash) == 13 && all(c -> isascii(c) && (isletter(c) || isdigit(c) || c in "./"), hash) &&
        return "descrypt"
    return "unknown"
end

"""Return the password state of an account: its hash scheme, or why it has none to carry.

`hashes` comes from `source_hashes`. Beyond `hash_scheme`'s answers this is
"missing" without an etc/shadow entry and "unreadable" when the file is.
"""
function password_state(hashes, name)
    hashes === nothing && return "unreadable"
    haskey(hashes, name) || return "missing"
    return hash_scheme(hashes[name])
end

"""Return true when a password in this state is a real hash worth carrying."""
carries_password(state) = !(state in ("locked", "empty", "missing", "unreadable", "unknown"))

"""Explain, for a log line, why a password in this state is not carried."""
function password_reason(state)
    state == "locked" && return "is locked in the source"
    state == "empty" && return "is empty in the source"
    state == "missing" && return "has no entry in the source's etc/shadow"
    state == "unreadable" && return "is unreadable: the source's etc/shadow cannot be read"
    return "uses a hash scheme pour does not know"
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

"""Return a home path as `/home/<name>`, or nothing when it is anything else.

The path comes from the source's passwd and becomes a destination that root
writes to, so only one plain component under /home is accepted: no `..`,
nothing deeper and nothing elsewhere.
"""
function safe_home(home)
    (startswith(home, '/') && !occursin('\0', home)) || return nothing
    parts = filter(p -> !isempty(p) && p != ".", split(home, '/'))
    any(==(".."), parts) && return nothing
    (length(parts) == 2 && parts[1] == "home") || return nothing
    return "/home/" * parts[2]
end

"""Return the first path below `base` on the way to `path` that is a symlink, or nothing.

The walk stops at the first component that does not exist, since nothing
under it can be a link yet.
"""
function symlink_on_path(base, path)
    p = base
    for part in splitpath(relpath(path, base))
        p = joinpath(p, part)
        islink(p) && return p
        ispath(p) || return nothing
    end
    return nothing
end

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
    hashes = source_hashes(root)
    failures = 0

    for u in human_users(root)
        home = safe_home(u.home)
        if home === nothing
            fail("$(u.name): home $(u.home) is not /home/<name>, skipping")
            failures += 1
            continue
        end
        src = source_path(root, home)
        dst = target_home(target, home)

        if !isdir(src)
            fail("$(u.name): home missing in source, $src")
            failures += 1
            continue
        end
        link = symlink_on_path(target, dst)
        if link !== nothing
            fail("$(u.name): $link is a symlink, not writing through it")
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
                                  "-d", home, "-s", u.shell, "--", u.name))
                ok("$(u.name): created user $(u.uid)")
            end
            state = password_state(hashes, u.name)
            if !carries_password(state)
                note("$(u.name): password $(password_reason(state)), account left locked")
                note("  set one on the new system with: passwd $(u.name)")
            elseif dry
                ok("$(u.name): would carry the password ($state)")
            else
                # The hash goes on stdin, never on a command line where ps can see it.
                runner(shadow_cmd("chpasswd", target, "-e"), "$(u.name):$(hashes[u.name])\n")
                ok("$(u.name): carried the password ($state)")
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

        stats = copy_tree(src, dst; dry = dry, owner = (uid = u.uid, gid = u.gid))
        ok(string(u.name, ": ", stats.files, " files, ", stats.links,
                 " symlinks, ", human(stats.bytes), dry ? " (planned)" : ""))
        stats.stripped > 0 && note(string(u.name, ": ", dry ? "would drop" : "dropped",
                                          " setuid/setgid from ", stats.stripped, " files"))
        stats.chowned > 0 && note(string(u.name, ": ", dry ? "would give" : "gave", " ",
                                         stats.chowned, " entries owned by another uid to ",
                                         u.name))

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
