# pour

Carry users, homes and package lists from an existing Linux system into joe.
A cup of joe from the old cup.

```
pour scan                   find existing Linux installs mounted on this machine
pour plan <root>            show what would be imported, changes nothing
pour run <root> --users     copy users, groups, homes and shell config
pour packages <root>        map the old system's packages to dave names
```

`plan` never writes. `run` refuses to touch a home directory that already
holds files, skips any account whose home is not `/home/<name>` or whose
name, uid or primary gid is already taken where it would go, and never
writes through a symlink on the way to a home. A problem with one account is
a `[FAIL]` line and a non-zero exit; the other accounts still go ahead.
`packages` prints a command and installs nothing. It reads dpkg and apk
databases; an rpm database is recognised but cannot be read yet.

`plan` and `run` take `--target <dir>` to work against another root, such as
a freshly installed disk mounted at /mnt/joe, instead of this machine:
accounts and groups go into its etc/passwd and etc/group through shadow's
`--prefix`, and homes into `<dir>/home`.

And every verb refuses a Euri Linux: Horizon source outright, with exit code 3. Horizon is
not something you migrate off **period**: update the machine with `horizon-update`
instead.

## For the installer

`scan`, `plan` and `run` take `--json` and then print one JSON object per
line on stdout instead of coloured lines. Exit codes stay the same: 0 done,
1 a problem, 2 a usage error, 3 a Horizon source.

    {"event":"system","device":"/dev/sda2","root":"/mnt/old","name":"Fedora Linux 42"}
    {"event":"account","name":"maja","uid":1000,"gid":1000,"home":"/home/maja",
     "files":5120,"bytes":73400320,"groups":["wheel","docker"],"admin":true,
     "password":"yescrypt","skip":null}
    {"event":"progress","account":"maja","files":500,"bytes":1048576}
    {"event":"result","account":"maja","ok":true,"problems":0,"message":null}
    {"event":"log","level":"ok","message":"maja: created user 1000"}
    {"event":"done"}
    {"event":"error","message":"1 account(s) had problems","code":1}

`system` comes from `scan`, and from `plan` and `run` for the source;
`device` is null when the root is not a mountpoint. `account` comes from
`plan`, and from `run` before each account is migrated; `skip` says why it
would be or was skipped, and `password` is the hash scheme or `locked`,
`empty`, `missing`, `unreadable` or `unknown`. `progress` and `result` come
from `run`. `log` carries every line the coloured output would have shown.
The last line is always `done` or `error`.

## What it keeps

- accounts, with the source uid and gid
- password hashes from etc/shadow, through `chpasswd -e`; a locked or empty
  one is not carried and that account stays locked
- supplemental group membership, creating groups that do not exist yet
- home directories, with their modes and symlinks; files lose setuid and
  setgid, and anything owned by another uid, such as root, is handed to the
  account
- a note when the source gave an account sudo, since joe uses doas

## Build and test

Julia 1.13. No dependencies outside the standard library.

    julia --project=. -e 'using Pkg; Pkg.test()'

Run it from the repository:

    julia --project=. -e 'using Pour; exit(Pour.main(ARGS))' plan /mnt/old

For one deployable directory:

    julia -e 'using PackageCompiler; create_app(".", "pour-bin"; incremental=false)'

## Layout

    src/Pour.jl       module, log helpers, dispatch
    src/json.jl       the --json event stream
    src/scan.jl       finding mounted installs
    src/plan.jl       the dry run
    src/run.jl        accounts, groups, copying, verification
    src/packages.jl   the name mapping table
    test/runtests.jl  the suite

## Licence

BSD-3-Clause. Every contribution in this repository is BSD-3-Clause, not MIT
and not GPL, including anything that lands in a repository whose own code is
MIT.
