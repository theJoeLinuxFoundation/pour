# SPDX-License-Identifier: BSD-3-Clause
# SPDX-FileCopyrightText: 2026 Ofek Bickel

"""Write `s` to `io` as a JSON string literal.

Quotes, backslashes and control characters are escaped; anything that is not
valid UTF-8, as a name in an old passwd may be, becomes U+FFFD.
"""
function json_string(io::IO, s::AbstractString)
    print(io, '"')
    for c in s
        if !isvalid(c)
            print(io, "\\ufffd")
        elseif c == '"'
            print(io, "\\\"")
        elseif c == '\\'
            print(io, "\\\\")
        elseif c == '\n'
            print(io, "\\n")
        elseif c == '\r'
            print(io, "\\r")
        elseif c == '\t'
            print(io, "\\t")
        elseif c < ' ' || c == '\x7f'
            print(io, "\\u", string(UInt32(c); base = 16, pad = 4))
        else
            print(io, c)
        end
    end
    print(io, '"')
end

"""Return `s` as a JSON string literal, see `json_string(io, s)`."""
json_string(s::AbstractString) = sprint(json_string, s)

"""Write a value as JSON: strings, integers, booleans, `nothing` as null,
vectors and tuples as arrays, and pairs or named tuples as objects in order."""
function json_value(io::IO, v)
    if v === nothing
        print(io, "null")
    elseif v isa Bool
        print(io, v ? "true" : "false")
    elseif v isa Integer
        print(io, v)
    elseif v isa AbstractString || v isa Symbol
        json_string(io, string(v))
    elseif v isa NamedTuple
        json_object(io, pairs(v))
    elseif v isa AbstractVector || v isa Tuple
        print(io, '[')
        for (i, x) in enumerate(v)
            i > 1 && print(io, ',')
            json_value(io, x)
        end
        print(io, ']')
    else
        throw(ArgumentError("no JSON form for $(typeof(v))"))
    end
end

"""Write `key => value` pairs as one JSON object, keeping their order."""
function json_object(io::IO, kvs)
    print(io, '{')
    for (i, (k, v)) in enumerate(kvs)
        i > 1 && print(io, ',')
        json_string(io, string(k))
        print(io, ':')
        json_value(io, v)
    end
    print(io, '}')
end

"""Print `{"event":kind,...}` with `fields` in order as one line, in `--json` mode only."""
function event(kind; fields...)
    JSON_OUTPUT[] || return nothing
    println(sprint(json_object, Any[:event => kind; collect(pairs(fields))]))
    return nothing
end

"""Run a verb with the output `args` ask for: coloured lines, or JSON events with `--json`.

In JSON mode the verb's last line is `{"event":"done"}` when it returns 0 and
`{"event":"error","message":...,"code":...}` otherwise, the message being its
last fail line. An exception there is an error event and exit 1, the code an
uncaught one would give, instead of a stack trace on stdout. Exit codes are
the verb's own either way.
"""
function with_output(verb, args)
    json = "--json" in args
    saved = JSON_OUTPUT[]
    JSON_OUTPUT[] = json
    LAST_FAIL[] = ""
    try
        code = try
            verb()
        catch e
            (json && !(e isa InterruptException)) || rethrow()
            fail(sprint(showerror, e))
            1
        end
        if code == 0
            event("done")
        else
            event("error"; message = isempty(LAST_FAIL[]) ? "exit code $code" : LAST_FAIL[],
                  code = code)
        end
        return code
    finally
        JSON_OUTPUT[] = saved
    end
end
