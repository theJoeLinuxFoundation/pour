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
