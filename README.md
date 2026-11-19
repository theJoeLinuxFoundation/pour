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
holds files. `packages` prints a command and installs nothing.

And every verb refuses a Horizon source outright, with exit code 3. Horizon is
not something you migrate off: update the machine with `horizon-update`
instead.

## What it keeps

- accounts, with the source uid and gid
- supplemental group membership, creating groups that do not exist yet
- home directories, with modes, owners and symlinks exactly as they were
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
    src/scan.jl       finding mounted installs
    src/plan.jl       the dry run
    src/run.jl        accounts, groups, copying, verification
    src/packages.jl   the name mapping table
    test/runtests.jl  the suite

## Licence

BSD-3-Clause. Every contribution in this repository is BSD-3-Clause, not MIT
and not GPL, including anything that lands in a repository whose own code is
MIT.
