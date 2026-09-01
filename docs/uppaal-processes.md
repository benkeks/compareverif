# ProVerif Processes in UPPAAL

`proverif_to_uppaal.py --uppaal-out MODEL.xml INPUT.pv` translates a restricted, static subset of ProVerif processes into UPPAAL templates. The translator first runs ProVerif with `-test` and translates its let-drifted intermediate process.

## Process Grammar

The supported top-level process forms are:

```text
step; step; ...; (proc1 | proc2 | ...)
step; step; ...
(proc1 | proc2 | ...)
```

The prefix or the parallel part may be omitted. Every parallel process becomes one UPPAAL template. A prefix becomes the `Prefix` template. Unsupported shapes produce an error explaining that the expected form is `(step; step; (proc1 | proc2))`, with either part optionally omitted.

The linear prefix can contain steps such as:

```text
new x: type;
insert table(value1, value2);
```

A `new` in the prefix creates a global name. An `insert` step calls the bounded insertion function generated for that table. The prefix finishes in a `terminated` location and then takes a dedicated broadcast transition to `forked`; parallel templates wait for this fork broadcast.

### Process Terms

The following process constructs are translated:

```text
new x: type; proc
insert table(value1, value2); proc
!proc
in(channel, x: type); proc
out(channel, value); proc
let x: type = value in proc
get table(x1: type, x2: type, ...) suchthat x1 = value in proc
if condition then proc else proc
```

- `new x: type` is translated as a fresh data identifier assignment.
- `insert table(value1, value2)` is translated as a function that inserts a fresh value into a small table.
- `!proc` is translated as a loop (instead of arbitrary width replication). The subprocess terminal transitions return to the replication location. Nested replication is rejected.
- `in(channel, x: type)` waits for a binary `channel?` synchronization and copies the channel payload into `x`.
- `out(channel, value)` writes `value` to the channel payload and emits `channel!`.
- A scalar `let` becomes an assignment from the value expression to the bound variable.
- `get` supports matching on some table field and binding every remaining table field. It generates getters named, for example, `table_get_second_by_first`. Conditions that match fields beyond the key, or otherwise contain matching logic not supported by this form, are rejected. A failed lookup follows a `get_failed` path; in a replicated process it loops back to the replication location.
- `if` creates guarded true and false transitions. Branch outcomes are laid out side by side.
- `event name(value)` is translated as a broadcast output on `name!`, with a global payload variable.

A communication channel must resolve to a global channel declaration. Dynamically bound channels, such as channels introduced by `new`, are rejected. Tuples are not supported as payloads or otherwise.

## Data Model

All translated ProVerif values use the global UPPAAL type:

```uppaal
typedef int [-1, (1 << 31) - 1] data;
```

Channel payloads, event payloads, table fields, free names, process bindings, and function arguments/results use `data`. Operational values such as table sizes, array indexes, capacities, constructor tags, and clocks remain `int` or `clock`.

If bigger data is needed the switch `--wide-data` can be used to generate a 63-bit `data` type using UPPAAL structs to pack four 16-bit ints.

### Constructors and Selectors

Functions declared with `fun` are classified as constructors unless their name appears on the left-hand side of a `reduc` rule. Reduction-rule functions are selectors. Declarations from locally resolvable `-lib` files are included.

Constructors receive four-bit datatype tags (limiting to fifteen constructors). Nullary constructors return their tag, unary constructors reserve the low four bits for the tag and shift their argument by four bits, and binary constructors use `BUILD_PAIR` to encode the tag, the first-argument width, and both arguments. Selectors inspect these tags and packed fields and return `-1` when their reduction pattern does not match.

Tuple data is not supported. Tuple bindings, tuple literals, and tuple values as function arguments are rejected. Input patterns must bind exactly one typed variable. Constructors with more than two arguments are rejected. A warning is emitted when a constructor term requires more than seven four-bit components in the 31-bit data range. (But there might be cases where this limit hits without a warning.)

Table storage has fixed capacity (currently three rows). Generated insertions stop when capacity is reached. Generated lookup functions return the first matching row or `-1` when no row matches.

## UPPAAL Pragmas

An input file can configure translation behavior through a YAML block in a ProVerif comment:

```text
(* UPPAAL
non_blocking_channels:
	- leak
time_channels:
	- tick
*)
```

`non_blocking_channels` declares channels as UPPAAL broadcast channels. It defaults to `leak`. `time_channels` selects which channels may use `in(channel, seconds(n))` timing annotations. It defaults to `tick`. Unknown pragma fields are ignored with a warning.

## Timing Annotations

The special input form:

```text
in(tick, seconds(n))
```

is treated as a timing annotation rather than a payload receive when `tick` is included in `time_channels`. It is translated to a spontaneous broadcast `tick!`, resets a component-local `seconds_clock`, and enters a location with invariant `seconds_clock <= n`. The continuation is enabled when `seconds_clock == n`. No payload variable is assigned, and `seconds` is not translated as a data constructor.

Other complex input patterns are rejected. Timing annotations use integer literal bounds in the current translator.

## Unsupported Features

The translator rejects or does not model:

- nested replication;
- dynamically bound communication channels;
- tuple data and tuple bindings;
- complex `in` patterns other than `seconds(n)`;
- `get` conditions that match beyond the first key;
- constructors with more than two arguments;
- process structures outside the supported linear-prefix/parallel forms

The generated model is intended as an executable approximation of the supported process control flow and data operations, not as a complete ProVerif semantics.
