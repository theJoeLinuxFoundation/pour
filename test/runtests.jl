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

"""Return a log and a runner that records commands and their stdin instead of running them."""
function recorder()
    log = Tuple{Vector{String},Union{Nothing,String}}[]
    record(cmd, input = nothing) = (push!(log, (cmd.exec, input)); true)
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
    @test occursin("account exists in $target", out)
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
