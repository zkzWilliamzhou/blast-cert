# Glossary

Domain language for `blast`. Architecture reviews use these names for domain concepts.

- **Command source**: the exact shell string under analysis. Never executed.
- **Word**: one shell word, made of parts. A word has a state: `literal`, `dynamic`, `opaque`, or `error`.
- **Word part**: a literal run, a quoted run, an escape, a variable reference, a command substitution, a backtick substitution, an arithmetic expansion, a glob, a tilde, or an ANSI-C quote.
- **Invocation**: one simple command with a resolved command name, arguments, redirects, and a source span.
- **Pipeline**: invocations connected by `|`. Order matters, since a producer feeding an interpreter forms an execution edge.
- **Capability**: a kind of effect a command can have. Examples: `FS_DELETE`, `FS_WRITE`, `NET_OUTBOUND`, `CODE_EVAL`, `PERSISTENCE`.
- **Assertion**: one capability claim with an action, an object, a scope, a confidence, a source span, a rule id, and a reason.
- **Unknown**: a fact the analyzer cannot determine. Unknowns block `allow`.
- **Opaque**: a construct the analyzer can see but cannot enumerate, such as `eval`, `source`, or a command substitution.
- **Evidence**: the concrete filesystem objects matched by a path assertion, with sizes, kinds, hashes, and sensitivity flags.
- **Root**: the directory the evidence resolver reads. All reported paths are relative to it.
- **Finding**: one matched filesystem object inside Evidence.
- **Decision**: `allow`, `confirm`, or `deny`, with reasons and an exit code.
- **Receipt**: a portable document binding Command source, assertions, Evidence, catalog digest, policy digest, and Decision under one SHA-256 digest.
- **Drift**: a difference between the filesystem state recorded in a Receipt and the state observed during `verify`.
- **Catalog**: the versioned, declarative rule set describing what known commands can do.
- **Policy**: the versioned rules describing what this caller permits.
- **Budget**: hard caps on input size, token count, matched files, and directory depth.

Architecture vocabulary, used exactly in `docs/architecture-review.html`: **module**, **interface**, **depth**, **seam**, **adapter**, **leverage**, **locality**, **deletion test**.
