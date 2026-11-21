# SPDX-License-Identifier: BSD-3-Clause
# SPDX-FileCopyrightText: 2026 Maja Wittbrodt

using Test
using Pour

"""Build a source tree with a nested directory and a symlink."""
function fixture()
    src = mktempdir()
    write(joinpath(src, "a.txt"), "hello")
    mkpath(joinpath(src, "sub"))
    write(joinpath(src, "sub", "b.txt"), "world")
    symlink("a.txt", joinpath(src, "link"))
    return src
end

"""Build a source root with os-release, passwd and group."""
function root_fixture(passwd, group)
    root = mktempdir()
    mkpath(joinpath(root, "etc"))
    write(joinpath(root, "etc", "os-release"), "PRETTY_NAME=\"Test Linux\"\n")
    write(joinpath(root, "etc", "passwd"), passwd)
    write(joinpath(root, "etc", "group"), group)
    return root
end

"""A yescrypt hash as it would sit in etc/shadow."""
const MAJA_HASH = "\$y\$j9T\$kV3cRkl2Q0Yy1mZ\$0mKZbPdQh3cX9y1tT8gW1o2B7l5Qe6Yr4uNcHs/AZ.8"

"""Build a source root holding one account with a small home and a password."""
function source_fixture()
    root = root_fixture(
        "root:x:0:0:root:/root:/bin/sh\n" *
        "maja:x:1000:1000:Maja:/home/maja:/bin/bash\n",
        "root:x:0:\nwheel:x:10:maja\ndocker:x:969:maja\nmaja:x:1000:\n")
    home = joinpath(root, "home", "maja")
    mkpath(joinpath(home, ".config"))
    write(joinpath(home, ".bashrc"), "export EDITOR=vim\n")
    write(joinpath(home, ".config", "app.conf"), "x=1\n")
    write(joinpath(root, "etc", "shadow"),
          "root:*:20000:0:99999:7:::\nmaja:$MAJA_HASH:20000:0:99999:7:::\n")
    return root
end

"""Build a target root, as a fresh joe install looks, with the given passwd and group."""
function target_fixture(passwd = "root:x:0:0:root:/root:/bin/sh\n", group = "root:x:0:\n")
    target = mktempdir()
    mkpath(joinpath(target, "etc"))
    mkpath(joinpath(target, "home"))
    write(joinpath(target, "etc", "passwd"), passwd)
    write(joinpath(target, "etc", "group"), group)
    return target
end

"""Run `f` with stdout sent to a file; return its result and everything it printed."""
function captured(f)
    path = tempname()
    result = open(path, "w") do io
        redirect_stdout(f, io)
    end
    return result, read(path, String)
end

"""Return a log and a runner that records commands and their stdin instead of running them.

Commands for which `failing` is true are recorded and then reported as failed.
"""
function recorder(; failing = c -> false)
    log = Tuple{Vector{String},Union{Nothing,String}}[]
    record(cmd, input = nothing) = (push!(log, (cmd.exec, input)); !failing(cmd.exec))
    return log, record
end

@testset "copy_tree keeps files, links and content" begin
    src = fixture()
    dst = joinpath(mktempdir(), "copy")
    stats = Pour.copy_tree(src, dst)
    @test stats.files == 2
    @test stats.links == 1
    @test read(joinpath(dst, "a.txt"), String) == "hello"
    @test read(joinpath(dst, "sub", "b.txt"), String) == "world"
    @test islink(joinpath(dst, "link"))
    @test readlink(joinpath(dst, "link")) == "a.txt"
end

@testset "copy_tree keeps modes" begin
    src = fixture()
    chmod(joinpath(src, "a.txt"), 0o640)
    dst = joinpath(mktempdir(), "copy")
    Pour.copy_tree(src, dst)
    @test (filemode(joinpath(dst, "a.txt")) & 0o777) == 0o640
end

@testset "verify_sample finds identical trees clean" begin
    src = fixture()
    dst = joinpath(mktempdir(), "copy")
    Pour.copy_tree(src, dst)
    v = Pour.verify_sample(src, dst)
    @test v.bad == 0
    @test v.checked == 2
end

@testset "verify_sample catches a changed file" begin
    src = fixture()
    dst = joinpath(mktempdir(), "copy")
    Pour.copy_tree(src, dst)
    write(joinpath(dst, "a.txt"), "tampered")
    v = Pour.verify_sample(src, dst)
    @test v.bad == 1
end

@testset "dry run writes nothing" begin
    src = fixture()
    dst = joinpath(mktempdir(), "copy")
    stats = Pour.copy_tree(src, dst; dry = true)
    @test stats.files == 2
    @test !isdir(dst)
end

@testset "human and measure" begin
    @test Pour.human(0) == "0 B"
    @test Pour.human(1024) == "1.0 KiB"
    @test Pour.human(1536) == "1.5 KiB"
    src = fixture()
    files, bytes = Pour.measure(src)
    @test files == 2
    @test bytes == 10
end

@testset "passwd parsing skips system accounts" begin
    root = root_fixture(
        "root:x:0:0:root:/root:/bin/sh\n" *
        "daemon:x:2:2:daemon:/sbin:/bin/false\n" *
        "maja:x:1000:1000:Maja:/home/maja:/bin/bash\n",
        "root:x:0:\nwheel:x:10:maja\nmaja:x:1000:\n")
    @test Pour.is_system(root)
    users = Pour.human_users(root)
    @test length(users) == 1
    @test users[1].name == "maja"
    @test users[1].uid == 1000
    @test Pour.describe(root) == "Test Linux"
end

@testset "group membership is read from the source" begin
    root = root_fixture(
        "maja:x:1000:1000:Maja:/home/maja:/bin/bash\n",
        "root:x:0:\nwheel:x:10:maja\ndocker:x:969:maja,toji\naudio:x:63:\n")
    groups = Pour.source_groups(root, "maja")
    names = sort([g[1] for g in groups])
    @test names == ["docker", "wheel"]
    @test Pour.source_groups(root, "nobody") == []
end

@testset "administrative rights are detected from the source" begin
    root = root_fixture(
        "maja:x:1000:1000:Maja:/home/maja:/bin/bash\n" *
        "toji:x:1001:1001:Toji:/home/toji:/bin/sh\n",
        "wheel:x:10:maja\nsudo:x:27:\ntoji:x:1001:\n")
    @test Pour.source_privileged(root, "maja")
    @test !Pour.source_privileged(root, "toji")
end

@testset "package mapping covers both naming conventions" begin
    @test Pour.PACKAGE_MAP["fd-find"] == "fd"
    @test Pour.PACKAGE_MAP["gcc"] == "clang"
    @test Pour.PACKAGE_MAP["network-manager"] == "networkmanager"
    @test Pour.PACKAGE_MAP["openssh-client"] == "openssh"
end

@testset "scan and packages refuse a non-root" begin
    empty_dir = mktempdir()
    @test !Pour.is_system(empty_dir)
    @test Pour.cmd_plan([empty_dir]) == 2
    @test Pour.cmd_packages([empty_dir]) == 2
end

@testset "status output goes through the log helpers" begin
    path = tempname()
    open(path, "w") do io
        redirect_stdout(io) do
            Pour.ok("thing worked")
            Pour.fail("thing broke")
            Pour.note("a note")
        end
    end
    out = read(path, String)
    @test occursin("thing worked", out)
    @test occursin("thing broke", out)
    @test occursin("a note", out)
    @test occursin("[ OK ]", out)
    @test occursin("[FAIL]", out)
end

@testset "Horizon is never a source" begin
    root = root_fixture(
        "maja:x:1000:1000:Maja:/home/maja:/bin/bash\n",
        "wheel:x:10:maja\n")
    write(joinpath(root, "etc", "os-release"),
          "NAME=\"Euri Linux\"\nPRETTY_NAME=\"Euri Linux: Horizon 26.11.11.3\"\nID=euri\n")
    @test Pour.is_horizon(root)
    @test Pour.cmd_plan([root]) == 3
    @test Pour.cmd_run([root, "--users", "--dry-run"]) == 3
    @test Pour.cmd_packages([root]) == 3
end

@testset "ordinary systems are not mistaken for Horizon" begin
    root = root_fixture(
        "maja:x:1000:1000:Maja:/home/maja:/bin/bash\n",
        "wheel:x:10:maja\n")
    write(joinpath(root, "etc", "os-release"),
          "NAME=\"Fedora Linux\"\nPRETTY_NAME=\"Fedora Linux 42\"\nID=fedora\n")
    @test !Pour.is_horizon(root)
end

@testset "options take values" begin
    pos, flags, opts = Pour.parse_args(["/mnt/old", "--users", "--target", "/mnt/joe"])
    @test pos == ["/mnt/old"]
    @test flags == Set(["--users"])
    @test opts["--target"] == "/mnt/joe"
    _, _, opts = Pour.parse_args(["--target=/mnt/joe"])
    @test opts["--target"] == "/mnt/joe"
    _, _, opts = Pour.parse_args(["/mnt/old", "--target"])
    @test opts["--target"] == ""
end

@testset "shadow commands get --prefix only for a target" begin
    @test Pour.shadow_cmd("groupadd", "/", "-g", 1000, "--", "maja").exec ==
          ["groupadd", "-g", "1000", "--", "maja"]
    @test Pour.shadow_cmd("useradd", "/mnt/joe", "-M", "--", "maja").exec ==
          ["useradd", "--prefix", "/mnt/joe", "-M", "--", "maja"]
end

@testset "run --target creates accounts and homes inside the target" begin
    root = source_fixture()
    target = target_fixture()
    log, runner = recorder()
    code, _ = captured(() -> Pour.cmd_run([root, "--users", "--target", target]; runner = runner))
    @test code == 0
    cmds = first.(log)
    @test all(c -> c[2:3] == ["--prefix", target], cmds)
    @test ["groupadd", "--prefix", target, "-g", "1000", "--", "maja"] in cmds
    @test ["useradd", "--prefix", target, "-M", "-u", "1000", "-g", "1000",
           "-d", "/home/maja", "-s", "/bin/bash", "--", "maja"] in cmds
    @test ["usermod", "--prefix", target, "-aG", "docker", "--", "maja"] in cmds
    @test read(joinpath(target, "home", "maja", ".bashrc"), String) == "export EDITOR=vim\n"
    @test isfile(joinpath(target, "home", "maja", ".config", "app.conf"))
end

@testset "a dry run with --target writes nothing" begin
    root = source_fixture()
    target = target_fixture()
    log, runner = recorder()
    code, _ = captured(() -> Pour.cmd_run([root, "--users", "--dry-run", "--target", target];
                                          runner = runner))
    @test code == 0
    @test isempty(log)
    @test !ispath(joinpath(target, "home", "maja"))
end

@testset "a target has to be a root" begin
    root = source_fixture()
    code, _ = captured(() -> Pour.cmd_run([root, "--users", "--target", mktempdir()]))
    @test code == 2
    code, _ = captured(() -> Pour.cmd_run([root, "--users", "--target"]))
    @test code == 2
    code, _ = captured(() -> Pour.cmd_plan([root, "--target", root]))
    @test code == 2
end

@testset "plan --target reads the target" begin
    root = source_fixture()
    target = target_fixture()
    code, out = captured(() -> Pour.cmd_plan([root, "--target", target]))
    @test code == 0
    @test occursin("would go to $(joinpath(target, "home", "maja"))", out)
    @test occursin("--target $target", out)
    target = target_fixture("maja:x:1000:1000::/home/maja:/bin/sh\n")
    _, out = captured(() -> Pour.cmd_plan([root, "--target", target]))
    @test occursin("maja: the name maja is taken in the target, would skip", out)
end

@testset "password hashes are named by scheme" begin
    @test Pour.hash_scheme(MAJA_HASH) == "yescrypt"
    @test Pour.hash_scheme("\$6\$salt\$hash") == "sha512crypt"
    @test Pour.hash_scheme("\$2b\$12\$hash") == "bcrypt"
    @test Pour.hash_scheme("abcdefghijk./") == "descrypt"
    @test Pour.hash_scheme("!") == "locked"
    @test Pour.hash_scheme("!!") == "locked"
    @test Pour.hash_scheme("!\$6\$salt\$hash") == "locked"
    @test Pour.hash_scheme("*") == "locked"
    @test Pour.hash_scheme("") == "empty"
    @test Pour.hash_scheme("x") == "unknown"
    @test Pour.password_state(Dict("maja" => MAJA_HASH), "toji") == "missing"
    @test Pour.password_state(nothing, "maja") == "unreadable"
    @test Pour.carries_password("yescrypt")
    @test !Pour.carries_password("locked")
end

@testset "run carries the hash on chpasswd's stdin" begin
    root = source_fixture()
    target = target_fixture()
    log, runner = recorder()
    code, _ = captured(() -> Pour.cmd_run([root, "--users", "--target", target]; runner = runner))
    @test code == 0
    @test (["chpasswd", "--prefix", target, "-e"], "maja:$MAJA_HASH\n") in log
    @test !any(c -> any(a -> occursin(MAJA_HASH, a), c), first.(log))
    @test findfirst(c -> c[1] == "chpasswd", first.(log)) >
          findfirst(c -> c[1] == "useradd", first.(log))
end

@testset "locked, empty and missing passwords are not carried" begin
    root = source_fixture()
    write(joinpath(root, "etc", "passwd"),
          "maja:x:1000:1000::/home/maja:/bin/bash\n" *
          "toji:x:1001:1001::/home/toji:/bin/sh\n" *
          "kim:x:1002:1002::/home/kim:/bin/sh\n")
    write(joinpath(root, "etc", "shadow"), "maja:!:20000::::::\ntoji::20000::::::\n")
    mkpath(joinpath(root, "home", "toji"))
    mkpath(joinpath(root, "home", "kim"))
    target = target_fixture()
    log, runner = recorder()
    code, out = captured(() -> Pour.cmd_run([root, "--users", "--target", target]; runner = runner))
    @test code == 0
    @test !any(c -> c[1] == "chpasswd", first.(log))
    @test occursin("maja: password is locked in the source, account left locked", out)
    @test occursin("toji: password is empty in the source, account left locked", out)
    @test occursin("kim: password has no entry in the source's etc/shadow", out)
    _, out = captured(() -> Pour.cmd_plan([root, "--target", target]))
    @test occursin("password locked", out)
    @test occursin("password empty", out)
end

@testset "plan names the hash scheme" begin
    root = source_fixture()
    _, out = captured(() -> Pour.cmd_plan([root, "--target", target_fixture()]))
    @test occursin("password yescrypt", out)
end

@testset "only /home/<name> is accepted as a home" begin
    @test Pour.safe_home("/home/maja") == "/home/maja"
    @test Pour.safe_home("/home/maja/") == "/home/maja"
    @test Pour.safe_home("//home//maja") == "/home/maja"
    @test Pour.safe_home("/home/./maja") == "/home/maja"
    @test Pour.safe_home("/home/../etc") === nothing
    @test Pour.safe_home("/home/maja/../../etc") === nothing
    @test Pour.safe_home("/home/..") === nothing
    @test Pour.safe_home("/home") === nothing
    @test Pour.safe_home("/home/maja/work") === nothing
    @test Pour.safe_home("/var/lib/maja") === nothing
    @test Pour.safe_home("/root") === nothing
    @test Pour.safe_home("home/maja") === nothing
    @test Pour.safe_home("") === nothing
end

@testset "run skips an account whose home leaves /home" begin
    root = source_fixture()
    write(joinpath(root, "etc", "passwd"),
          "maja:x:1000:1000::/home/../etc:/bin/bash\n" *
          "toji:x:1001:1001::/home/toji/../../../../tmp:/bin/sh\n")
    mkpath(joinpath(root, "etc", "fake"))
    target = target_fixture()
    log, runner = recorder()
    code, out = captured(() -> Pour.cmd_run([root, "--users", "--target", target]; runner = runner))
    @test code == 1
    @test isempty(log)
    @test occursin("[FAIL] maja: home /home/../etc is not /home/<name>, skipping", out)
    @test occursin("[FAIL] toji: home", out)
    @test readdir(joinpath(target, "home")) == []
    _, out = captured(() -> Pour.cmd_plan([root, "--target", target]))
    @test occursin("maja: home /home/../etc is not /home/<name>, would skip", out)
end

@testset "run never writes through a symlink in the destination" begin
    for linked in ("home", joinpath("home", "maja"))
        root = source_fixture()
        target = target_fixture()
        elsewhere = mktempdir()
        rm(joinpath(target, linked); recursive = true, force = true)
        mkpath(dirname(joinpath(target, linked)))
        symlink(elsewhere, joinpath(target, linked))
        log, runner = recorder()
        code, out = captured(() -> Pour.cmd_run([root, "--users", "--target", target];
                                                runner = runner))
        @test code == 1
        @test isempty(log)
        @test occursin("$(joinpath(target, linked)) is a symlink, not writing through it", out)
        @test isempty(readdir(elsewhere))
    end
end

@testset "copy_tree refuses a symlinked destination" begin
    src = fixture()
    elsewhere = mktempdir()
    dst = joinpath(mktempdir(), "copy")
    symlink(elsewhere, dst)
    @test_throws ErrorException Pour.copy_tree(src, dst)
    @test isempty(readdir(elsewhere))
    @test Pour.symlink_on_path(dirname(dst), joinpath(dst, "sub", "file")) == dst
    @test Pour.symlink_on_path(elsewhere, joinpath(elsewhere, "a", "b")) === nothing
end

@testset "copy_tree drops setuid and setgid from files" begin
    src = fixture()
    chmod(joinpath(src, "a.txt"), 0o4755)
    chmod(joinpath(src, "sub", "b.txt"), 0o2750)
    @test filemode(joinpath(src, "a.txt")) & 0o4000 != 0
    dst = joinpath(mktempdir(), "copy")
    stats = Pour.copy_tree(src, dst)
    @test stats.stripped == 2
    @test filemode(joinpath(dst, "a.txt")) & 0o7777 == 0o755
    @test filemode(joinpath(dst, "sub", "b.txt")) & 0o7777 == 0o750
    @test Pour.copy_tree(src, joinpath(mktempdir(), "copy"); dry = true).stripped == 2
end

@testset "copy_tree hands entries of other uids to the account" begin
    @test Pour.new_owner(0, 0, (uid = 1000, gid = 1000)) == (1000, 1000, true)
    @test Pour.new_owner(1000, 969, (uid = 1000, gid = 1000)) == (1000, 969, false)
    @test Pour.new_owner(0, 0, nothing) == (0, 0, false)
    src = fixture()
    me = (uid = Int(ccall(:getuid, Cuint, ())), gid = Int(ccall(:getgid, Cuint, ())))
    @test Pour.copy_tree(src, joinpath(mktempdir(), "copy"); owner = me).chowned == 0
    other = (uid = me.uid + 1, gid = me.gid + 1)
    # two files, a symlink and two directories belong to someone else
    @test Pour.copy_tree(src, joinpath(mktempdir(), "copy"); dry = true, owner = other).chowned == 5
end

@testset "run reports the setuid files it defused" begin
    root = source_fixture()
    chmod(joinpath(root, "home", "maja", ".bashrc"), 0o6755)
    target = target_fixture()
    _, runner = recorder()
    code, out = captured(() -> Pour.cmd_run([root, "--users", "--target", target]; runner = runner))
    @test code == 0
    @test occursin("maja: dropped setuid/setgid from 1 files", out)
    @test filemode(joinpath(target, "home", "maja", ".bashrc")) & 0o7777 == 0o755
end

@testset "run_cmd turns failures into fail lines" begin
    @test captured(() -> Pour.run_cmd(`true`))[1]
    code, out = captured(() -> Pour.run_cmd(`sh -c 'echo oops >&2; exit 4'`))
    @test !code
    @test occursin("[FAIL] sh failed with exit code 4: oops", out)
    code, out = captured(() -> Pour.run_cmd(`pour-no-such-command-here`))
    @test !code
    @test occursin("[FAIL] pour-no-such-command-here could not run", out)
    code, out = captured(() -> Pour.run_cmd(`cat`, "fed on stdin\n"))
    @test code
    @test occursin("cat: fed on stdin", out)
end

@testset "names that a command line could misread are refused" begin
    @test Pour.valid_name("maja")
    @test Pour.valid_name("john.doe")
    @test Pour.valid_name("build\$")
    @test !Pour.valid_name("-oops")
    @test !Pour.valid_name("audio,wheel")
    @test !Pour.valid_name("1000")
    @test !Pour.valid_name("")
    @test !Pour.valid_name("a"^33)
end

@testset "a uid, name or gid taken in the target skips the account" begin
    cases = [
        ("joe:x:1000:1000::/home/joe:/bin/sh\n", "root:x:0:\n",
         "uid 1000 is taken by joe in the target"),
        ("maja:x:1001:1001::/home/maja:/bin/sh\n", "root:x:0:\n",
         "the name maja is taken in the target"),
        ("root:x:0:0::/root:/bin/sh\n", "users:x:1000:\n",
         "gid 1000 is taken by group users in the target"),
        ("root:x:0:0::/root:/bin/sh\n", "maja:x:1001:\n",
         "group maja has gid 1001 in the target, not 1000"),
    ]
    for (passwd, group, why) in cases
        root = source_fixture()
        target = target_fixture(passwd, group)
        log, runner = recorder()
        code, out = captured(() -> Pour.cmd_run([root, "--users", "--target", target];
                                                runner = runner))
        @test code == 1
        @test isempty(log)
        @test occursin("[FAIL] maja: $why, skipping", out)
        @test isempty(readdir(joinpath(target, "home")))
        code, out = captured(() -> Pour.cmd_plan([root, "--target", target]))
        @test code == 0
        @test occursin("maja: $why, would skip", out)
    end
end

@testset "a primary group the target already has is reused" begin
    root = root_fixture(
        "maja:x:1000:100::/home/maja:/bin/bash\ntoji:x:1001:100::/home/toji:/bin/sh\n",
        "users:x:100:\n")
    mkpath(joinpath(root, "home", "maja"))
    mkpath(joinpath(root, "home", "toji"))
    for group in ("users:x:100:\n", "root:x:0:\n")
        target = target_fixture("root:x:0:0::/root:/bin/sh\n", group)
        log, runner = recorder()
        code, _ = captured(() -> Pour.cmd_run([root, "--users", "--target", target];
                                              runner = runner))
        @test code == 0
        groupadds = filter(c -> c[1] == "groupadd", first.(log))
        # created once when the target lacks it, never when it has it already
        @test length(groupadds) == (startswith(group, "users") ? 0 : 1)
        @test count(c -> c[1] == "useradd", first.(log)) == 2
    end
end

@testset "a failing command is a fail line, not an exception" begin
    root = source_fixture()
    write(joinpath(root, "etc", "passwd"),
          "maja:x:1000:1000::/home/maja:/bin/bash\ntoji:x:1001:1001::/home/toji:/bin/sh\n")
    mkpath(joinpath(root, "home", "toji"))
    write(joinpath(root, "home", "toji", "notes"), "hi")
    target = target_fixture()
    log, runner = recorder(failing = c -> c[1] == "useradd" && c[end] == "maja")
    code, out = captured(() -> Pour.cmd_run([root, "--users", "--target", target]; runner = runner))
    @test code == 1
    @test occursin("[FAIL] maja: could not create user 1000", out)
    @test occursin("1 account(s) had problems", out)
    # maja stops at the failed useradd; toji still goes ahead
    @test !any(c -> c[1] == "chpasswd", first.(log))
    @test !ispath(joinpath(target, "home", "maja"))
    @test read(joinpath(target, "home", "toji", "notes"), String) == "hi"

    log, runner = recorder(failing = c -> c[1] == "usermod")
    code, out = captured(() -> Pour.cmd_run([root, "--users", "--target", target_fixture()];
                                            runner = runner))
    @test code == 1
    @test occursin("[FAIL] maja: could not join group docker", out)
end

@testset "groups with a bad name or a taken gid are not joined" begin
    root = source_fixture()
    write(joinpath(root, "etc", "group"),
          "maja:x:1000:\naudio,wheel:x:63:maja\nplugdev:x:46:maja\n")
    target = target_fixture("root:x:0:0::/root:/bin/sh\n", "root:x:0:\nlp:x:46:\n")
    log, runner = recorder()
    code, out = captured(() -> Pour.cmd_run([root, "--users", "--target", target]; runner = runner))
    @test code == 1
    @test occursin("group name audio,wheel is not one groupadd takes", out)
    @test occursin("gid 46 of group plugdev is taken by lp in the target", out)
    @test !any(c -> c[1] == "usermod", first.(log))
    @test isfile(joinpath(target, "home", "maja", ".bashrc"))
end
