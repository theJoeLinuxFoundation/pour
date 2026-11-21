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

"""The names and ids already taken in a root's passwd and group files."""
struct Taken
    users::Dict{String,Int}
    uids::Dict{Int,String}
    groups::Dict{String,Int}
    gids::Dict{Int,String}
end

"""Record that a user name and uid are taken."""
take_user!(t::Taken, name, uid) = (t.users[name] = uid; get!(t.uids, uid, name); t)

"""Record that a group name and gid are taken."""
take_group!(t::Taken, name, gid) = (t.groups[name] = gid; get!(t.gids, gid, name); t)

"""Read the names and ids taken under `target`, this machine by default."""
function taken_ids(target = "/")
    t = Taken(Dict(), Dict(), Dict(), Dict())
    for f in read_passwd(joinpath(target, "etc", "passwd"))
        length(f) >= 3 || continue
        id = tryparse(Int, f[3])
        id === nothing || take_user!(t, f[1], id)
    end
    for f in read_passwd(joinpath(target, "etc", "group"))
        length(f) >= 3 || continue
        id = tryparse(Int, f[3])
        id === nothing || take_group!(t, f[1], id)
    end
    return t
end

"""Return true for a user or group name that shadow takes and no command line misreads.

Letters, digits, `_`, `.` and `-`, starting with a letter, digit or `_`,
optionally ending in `\$`, not all digits and at most 32 characters. That
rules out a leading dash, read as an option, and a comma, read by usermod
as a second group.
"""
function valid_name(name)
    length(name) <= 32 || return false
    occursin(r"^[A-Za-z0-9_][A-Za-z0-9_.-]*\$?$", name) || return false
    return !all(isdigit, name)
end

"""Return the name of an account's primary group in the source, or its own name without one."""
function primary_group(root, u)
    for f in read_passwd(joinpath(root, "etc", "group"))
        length(f) >= 3 && tryparse(Int, f[3]) == u.gid && return f[1]
    end
    return u.name
end

"""Return why an account cannot be created in the target, or nothing when it can.

Its name and uid have to be free there. Its primary group has to be either
absent, so it can be created with the source's gid, or present with the same
name and gid, as `users` often is; anything else would hand the account
someone else's group.
"""
function account_conflict(u, group, ids)
    valid_name(u.name) || return "the name $(u.name) is not one useradd takes"
    haskey(ids.users, u.name) && return "the name $(u.name) is taken in the target"
    haskey(ids.uids, u.uid) && return "uid $(u.uid) is taken by $(ids.uids[u.uid]) in the target"
    valid_name(group) || return "its group name $group is not one groupadd takes"
    by_gid = get(ids.gids, u.gid, nothing)
    by_gid === nothing || by_gid == group ||
        return "gid $(u.gid) is taken by group $by_gid in the target"
    by_name = get(ids.groups, group, nothing)
    by_name === nothing || by_name == u.gid ||
        return "group $group has gid $by_name in the target, not $(u.gid)"
    return nothing
end

"""Check an account against the source and the target before anything is written.

Returns its normalised `home`, the `src` and `dst` of that home, its primary
`group`, and `problem`: why it has to be skipped, or nothing when it can go.
`src` and `dst` are empty when the home path itself is refused.
"""
function check_account(u, root, target, ids)
    home = safe_home(u.home)
    if home === nothing
        return (problem = "home $(u.home) is not /home/<name>", home = u.home,
                src = "", dst = "", group = u.name)
    end
    src = source_path(root, home)
    dst = target_home(target, home)
    group = primary_group(root, u)
    link = symlink_on_path(target, dst)
    problem = if !is_dir(src)
        "home missing in source, $src"
    elseif link !== nothing
        "$link is a symlink, not writing through it"
    elseif is_dir(dst) && !isempty(readdir(dst))
        "$dst already has files, not touching it"
    else
        account_conflict(u, group, ids)
    end
    return (problem = problem, home = home, src = src, dst = dst, group = group)
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

"""Run an external command with `input` on its stdin; return true when it exits zero.

Its output is collected instead of mixed into pour's: on success each line
becomes a note, on failure it goes into the fail line. A command that cannot
start or exits non-zero is a fail line and false, never an exception.
"""
function run_cmd(cmd, input = nothing)
    out = IOBuffer()
    proc = try
        run(pipeline(ignorestatus(cmd); stdin = input === nothing ? devnull : IOBuffer(input),
                     stdout = out, stderr = out))
    catch e
        e isa InterruptException && rethrow()
        fail("$(cmd.exec[1]) could not run: $(sprint(showerror, e))")
        return false
    end
    lines = split(strip(String(take!(out))), '\n'; keepempty = false)
    if success(proc)
        foreach(line -> note("  $(cmd.exec[1]): $line"), lines)
        return true
    end
    how = proc.termsignal > 0 ? "was killed by signal $(proc.termsignal)" :
          "failed with exit code $(proc.exitcode)"
    fail("$(cmd.exec[1]) $how" * (isempty(lines) ? "" : ": " * join(lines, "; ")))
    return false
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

"""Run one shadow command against the target, or only say so in a dry run.

`what` pairs the step with its past tense, such as `"create user 1000" =>
"created user 1000"`, for the ok line. A failed step gets a fail line naming
the account, after the one `run_cmd` printed. Returns false only on failure.
"""
function step(ctx, name, what, tool, args...; input = nothing)
    if ctx.dry
        ok("$name: would $(first(what))")
        return true
    end
    if !ctx.runner(shadow_cmd(tool, ctx.target, args...), input)
        fail("$name: could not $(first(what))")
        return false
    end
    ok("$name: $(last(what))")
    return true
end

"""Migrate one account: create its group and user, carry its password, join
its groups and copy its home.

Every problem is a fail line; the result is how many there were. An account
that fails `check_account`, or whose group or user cannot be created, is left
alone after the first.
"""
function migrate_account(u, ctx)
    c = check_account(u, ctx.root, ctx.target, ctx.ids)
    if c.problem !== nothing
        fail("$(u.name): $(c.problem), skipping")
        return 1
    end

    if !haskey(ctx.ids.groups, c.group)
        step(ctx, u.name, "create group $(c.group) ($(u.gid))" => "created group $(c.group) ($(u.gid))",
             "groupadd", "-g", u.gid, "--", c.group) || return 1
        take_group!(ctx.ids, c.group, u.gid)
    end
    step(ctx, u.name, "create user $(u.uid)" => "created user $(u.uid)",
         "useradd", "-M", "-u", u.uid, "-g", u.gid, "-d", c.home, "-s", u.shell,
         "--", u.name) || return 1
    take_user!(ctx.ids, u.name, u.uid)
    problems = 0

    state = password_state(ctx.hashes, u.name)
    if carries_password(state)
        # The hash goes on stdin, never on a command line where ps can see it.
        step(ctx, u.name, "carry the password ($state)" => "carried the password ($state)",
             "chpasswd", "-e"; input = "$(u.name):$(ctx.hashes[u.name])\n") || (problems += 1)
    else
        note("$(u.name): password $(password_reason(state)), account left locked")
        note("  set one on the new system with: passwd $(u.name)")
    end

    for (gname, gid) in source_groups(ctx.root, u.name)
        gname in ("wheel", "sudo", "admin") && continue
        gname == c.group && continue
        if !valid_name(gname)
            fail("$(u.name): group name $gname is not one groupadd takes, not joining it")
            problems += 1
            continue
        end
        if !haskey(ctx.ids.groups, gname)
            if haskey(ctx.ids.gids, gid)
                fail("$(u.name): gid $gid of group $gname is taken by " *
                     "$(ctx.ids.gids[gid]) in the target, not joining it")
                problems += 1
                continue
            end
            if !step(ctx, u.name, "create group $gname ($gid)" => "created group $gname ($gid)",
                     "groupadd", "-g", gid, "--", gname)
                problems += 1
                continue
            end
            take_group!(ctx.ids, gname, gid)
        end
        step(ctx, u.name, "join group $gname" => "joined group $gname",
             "usermod", "-aG", gname, "--", u.name) || (problems += 1)
    end

    stats = copy_tree(c.src, c.dst; dry = ctx.dry, owner = (uid = u.uid, gid = u.gid))
    ok(string(u.name, ": ", stats.files, " files, ", stats.links,
             " symlinks, ", human(stats.bytes), ctx.dry ? " (planned)" : ""))
    stats.stripped > 0 && note(string(u.name, ": ", ctx.dry ? "would drop" : "dropped",
                                      " setuid/setgid from ", stats.stripped, " files"))
    stats.chowned > 0 && note(string(u.name, ": ", ctx.dry ? "would give" : "gave", " ",
                                     stats.chowned, " entries owned by another uid to ", u.name))

    if ctx.verify && !ctx.dry
        v = verify_sample(c.src, c.dst)
        if v.bad == 0
            ok("$(u.name): verified $(v.checked) files")
        else
            fail("$(u.name): $(v.bad) of $(v.checked) files differ")
            problems += 1
        end
    end
    return problems
end

"""The `run` verb: create accounts and copy their homes.

`runner` executes each external command, see `run_cmd`; tests pass one that
records them. A problem with one account is a fail line and a non-zero exit,
and the other accounts still go ahead.
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
    ctx = (root = root, target = target, dry = dry, verify = verify, runner = runner,
           ids = taken_ids(target), hashes = source_hashes(root))
    failures = 0

    for u in human_users(root)
        problems = try
            migrate_account(u, ctx)
        catch e
            e isa InterruptException && rethrow()
            fail("$(u.name): $(sprint(showerror, e))")
            1
        end
        failures += problems > 0
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
