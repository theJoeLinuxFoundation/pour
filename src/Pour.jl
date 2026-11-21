# SPDX-License-Identifier: BSD-3-Clause
# SPDX-FileCopyrightText: 2026 Maja Wittbrodt

"""Pour: carry users, homes and package lists from an existing Linux system into joe.

The verbs are `scan`, `plan`, `run` and `packages`. `plan` is dry-run by
construction: it reports and never writes.
"""
module Pour

using SHA

export main

const VERSION_STR = "pour 0.1.0 (horizon)"

const TTY = isa(stdout, Base.TTY)
const OK = TTY ? "\e[1;32m[ OK ]\e[0m" : "[ OK ]"
const FAIL = TTY ? "\e[1;31m[FAIL]\e[0m" : "[FAIL]"
const NOTE = TTY ? "\e[1;34mpour:\e[0m" : "pour:"

"""True while a verb prints JSON events instead of coloured lines, see `with_output`."""
const JSON_OUTPUT = Ref(false)

"""The last fail line, which becomes the message of a JSON error event."""
const LAST_FAIL = Ref("")

"""Print a success line in the dinit shape, or a log event in `--json` mode."""
ok(msg) = JSON_OUTPUT[] ? event("log"; level = "ok", message = msg) : println("$OK $msg")

"""Print a failure line in the dinit shape, or a log event in `--json` mode."""
function fail(msg)
    LAST_FAIL[] = msg
    return JSON_OUTPUT[] ? event("log"; level = "fail", message = msg) : println("$FAIL $msg")
end

"""Print a prose line prefixed with the program name, or a log event in `--json` mode."""
note(msg) = JSON_OUTPUT[] ? event("log"; level = "note", message = msg) : println("$NOTE $msg")

"""Print an empty line between sections, except in `--json` mode."""
blank() = JSON_OUTPUT[] || println()

"""Print the usage text."""
function usage()
    println("""
pour $VERSION_STR

  pour scan                   find existing Linux installs mounted on this machine
  pour plan <root>            show what would be imported, changes nothing
  pour run <root> [--users]   copy users, groups, homes and shell config
  pour run <root> --dry-run   same, but write nothing
  pour packages <root>        map the old system's packages to dave names

Options
  --target DIR  create accounts and homes in the root at DIR, such as a
                freshly installed disk, instead of on this machine
  --dry-run     never write to this machine, to <root> or to the target
  --verify      compare hashes after copying (default on)
  --no-verify   skip the hash pass, counts only
  --json        for scan, plan and run: one JSON event per line on stdout
  --help        this text
  --version     print the version
""")
end

"""lstat that returns nothing instead of throwing on unreadable paths."""
function safe_lstat(path)
    return try
        lstat(path)
    catch
        nothing
    end
end

"""True when a path is a regular file, without throwing on permission errors."""
function is_file(path)
    st = safe_lstat(path)
    return st !== nothing && isfile(path)
end

"""True when a path is a directory, without throwing on permission errors."""
function is_dir(path)
    return try
        isdir(path)
    catch
        false
    end
end

"""Read /etc/passwd style files into a vector of field vectors."""
function read_passwd(path)
    out = Vector{Vector{String}}()
    isfile(path) || return out
    for line in eachline(path)
        isempty(strip(line)) && continue
        startswith(line, '#') && continue
        push!(out, String.(split(line, ':')))
    end
    return out
end

"""Read key=value files such as os-release into a Dict."""
function read_kv(path)
    d = Dict{String,String}()
    isfile(path) || return d
    for line in eachline(path)
        s = strip(line)
        (isempty(s) || startswith(s, '#')) && continue
        i = findfirst('=', s)
        i === nothing && continue
        k = s[1:prevind(s, i)]
        v = s[nextind(s, i):end]
        v = strip(v, ['"', '\''])
        d[String(k)] = String(v)
    end
    return d
end

"""Return true when the source root is Horizon, which pour refuses to leave."""
function is_horizon(root)
    kv = read_kv(joinpath(root, "etc", "os-release"))
    text = lowercase(join((get(kv, "ID", ""), get(kv, "NAME", ""),
                           get(kv, "PRETTY_NAME", "")), " "))
    return occursin("horizon", text) || occursin("euri", text)
end

"""Refuse a Horizon source, because you do not migrate off Horizon."""
function refuse_horizon(root)
    is_horizon(root) || return false
    fail("this is Horizon: not migrating")
    note("pour does not carry anyone off Horizon")
    note("update the machine instead: horizon-update")
    note("if you really meant a different source root, pass that path")
    return true
end

"""Return true when `root` looks like an installed system."""
function is_system(root)
    return is_file(joinpath(root, "etc", "os-release")) &&
           is_file(joinpath(root, "etc", "passwd"))
end

"""Describe a system root from its os-release."""
function describe(root)
    kv = read_kv(joinpath(root, "etc", "os-release"))
    name = get(kv, "PRETTY_NAME", get(kv, "NAME", "unknown"))
    return name
end

"""Count files and bytes under `dir`, never following symlinks."""
function measure(dir)
    files = 0
    bytes = 0
    isdir(dir) || return (files, bytes)
    for (root, _, fs) in walkdir(dir; follow_symlinks = false)
        for f in fs
            p = joinpath(root, f)
            st = safe_lstat(p)
            st === nothing && continue
            islink(p) && continue
            files += 1
            bytes += st.size
        end
    end
    return (files, bytes)
end

"""Format a byte count for humans."""
function human(bytes)
    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    v = Float64(bytes)
    i = 1
    while v >= 1024 && i < length(units)
        v /= 1024
        i += 1
    end
    return i == 1 ? "$(Int(v)) $(units[i])" : string(round(v; digits = 1), " ", units[i])
end

"""Split `args` into positionals, flags and options without a dependency.

The options named in `valued` take a value, as `--target DIR` or
`--target=DIR`; one given with nothing after it gets the empty string.
"""
function parse_args(args; valued = ("--target",))
    flags = Set{String}()
    pos = String[]
    opts = Dict{String,String}()
    i = 1
    while i <= length(args)
        a = args[i]
        eq = findfirst('=', a)
        name = eq === nothing ? a : a[1:prevind(a, eq)]
        if startswith(a, "--") && name in valued
            if eq !== nothing
                opts[name] = a[nextind(a, eq):end]
            elseif i < length(args)
                i += 1
                opts[name] = args[i]
            else
                opts[name] = ""
            end
        elseif startswith(a, "--")
            push!(flags, a)
        else
            push!(pos, a)
        end
        i += 1
    end
    return pos, flags, opts
end

"""Return the root that accounts are written into, or nothing after a fail line.

Without `--target` that is this machine, `/`. With it, the directory must hold
etc/passwd and etc/group, as a freshly installed joe does, and must not be
the source root itself.
"""
function target_root(opts, source)
    haskey(opts, "--target") || return "/"
    dir = opts["--target"]
    if isempty(dir)
        fail("--target needs a directory: --target /mnt/joe")
        return nothing
    end
    dir = abspath(dir)
    dir = dir == "/" ? dir : rstrip(dir, '/')
    if !(is_file(joinpath(dir, "etc", "passwd")) && is_file(joinpath(dir, "etc", "group")))
        fail("$dir is not a target root: no etc/passwd and etc/group")
        return nothing
    end
    if realpath(dir) == realpath(source)
        fail("$dir is the source root, not a target")
        return nothing
    end
    return String(dir)
end

include("json.jl")
include("scan.jl")
include("plan.jl")
include("run.jl")
include("packages.jl")

"""Dispatch the verbs."""
function main(args)
    isempty(args) && (usage(); return 0)
    verb = args[1]
    rest = args[2:end]
    if verb in ("-h", "--help", "help")
        usage()
        return 0
    elseif verb in ("-V", "--version", "version")
        println(VERSION_STR)
        return 0
    elseif verb == "scan"
        return cmd_scan(rest)
    elseif verb == "plan"
        return cmd_plan(rest)
    elseif verb == "run"
        return cmd_run(rest)
    elseif verb == "packages"
        return cmd_packages(rest)
    end
    fail("unknown verb: $verb")
    usage()
    return 2
end

end # module
