# artifact

[![pkg.go.dev](https://img.shields.io/badge/pkg.go.dev-artifact-007d9c?logo=go&logoColor=white)](https://pkg.go.dev/github.com/go-zpkg/artifact)
![Go](https://img.shields.io/badge/Go-1.27%2B-00ADD8?logo=go&logoColor=white)
![License](https://img.shields.io/badge/license-BSD--3--Clause-blue)

The pure-Go **artifact client** — the shared backend of the `zpkgx` family. It
resolves a package's dependency closure, downloads the artifacts from the
configured `ZPKG_DIST` (default: `oci://ghcr.io/go-pkgx/packages`, the signed
registry the published artifacts are actually in — see `DistBase` in `zpkg.go`),
completes the implicit libc/gcc closure a `FROM scratch` image needs, and
execs through the glibc artifact's own loader. `CGO_ENABLED=0`, no runtime
dependencies of its own.

Consumed by:

- [go-zpkg/zpkgm](https://github.com/go-zpkg/zpkgm) — the *installer*
- [go-zpkg/zpkgx](https://github.com/go-zpkg/zpkgx) — the *runtime*

so both tools share one source of truth for the artifact protocol.

## Highlights

- Reads `package.hcl` + `versions.txt` from the pantry — falling back to
  `package.yml`, which is **converted to HCL on the way in** (`zpkg.go:276`)
  and is being retired with the rest of the pkgx compatibility — then BFS the
  runtime dependency closure and streams gzip/xz + tar into `ZPKG_DIR`.
  ⛔ "The pantry" is **two** trees: our own recipes merged over
  `pkgxdev/pantry`, which `PantryBase` still reads at resolve time
  (`zpkg.go:68`) and which is a dependency being wound down — the sovereign
  pantry is written, not converted, because that corpus carries no licence to
  convert (go-zpkg/packages#431, #440).
- **Soname-exact FROM-scratch completion**: walks each artifact's ELF
  `DT_NEEDED` and pulls the provider version that ships the exact soname an
  ABI needs (not merely the latest), so drifted sonames resolve.
- Embedded Mozilla CA bundle (`net/http` with no system trust store), pure-Go
  DNS.
- **Nothing outside the store.** A blob is staged inside `$ZPKG_DIR`, not in
  the system temp directory: `FROM scratch` has no `/tmp`, and until this was
  measured by building that image and running it, `zpkgs catalog update` failed
  on the one image this package exists to serve.

## What `Extract` refuses

`Extract` is the one tar extractor in this ecosystem, and it is pointed at
archives nobody here produced: artifacts from a registry, and — through
`zbk/fetch` — **source tarballs from 233 distinct upstream hosts**, unpacked as
root inside a chroot in the sovereign build. So what it refuses is part of its API,
not an implementation detail.

| it rejects with `ErrInsecurePath` | why |
| --- | --- |
| an absolute entry name | `/etc/passwd` is not inside anything |
| a name that escapes `dest` after component-stripping | the classic `../..` |
| a hard-link **source** that escapes `dest` | vetted exactly like a name |
| an entry whose path **crosses a symlink an earlier entry created** | a name check is lexical and a write is not: `dest/a/b` is inside `dest` even when `a` is a link out of it |

and it drops **setuid, setgid and sticky** — an entry gets its permission bits
and nothing else.

A leaf that an earlier entry made a symlink is unlinked rather than refused,
because the archive does say what belongs at that name. A *directory
component* that is already a symlink is refused, because there the archive
contradicts itself.

**What it does not promise.** A symlink *entry* may point anywhere, including
out of `dest` — that is what `tar(1)` does, and artifacts need relative links.
Nothing `Extract` writes afterwards follows such a link, but a caller that
walks the result and resolves symlinks itself can still leave `dest`, and has
to say whether it means to.

Each of these rules has a test that fails without it, and a positive control
that an ordinary nested archive still extracts: a check tightened too far
refuses everything and reports green.

## What bounds an `.xz` artifact

`Decompressor` decodes `.tar.xz` with
[`go-compressions/xz`](https://github.com/go-compressions/xz), not
`ulikunitz/xz`. The latter allocates the LZMA2 dictionary whole from the block
header (`DictCap` is a minimum, not a ceiling): a 44-byte `.xz` declaring a
1.5 GiB dictionary allocated 1,610,663,976 bytes, and an artifact or a source
tarball is input nobody here produced. Here the window grows with the decoded
data: a stream declaring 1.5 GiB over a few bytes allocates about 22 KB
(`decompress_bomb_test.go`, run in CI as a compiled binary under `ulimit -v`
and `GOMEMLIMIT`). The dictionary a stream may make the decoder keep is capped
at 256 MiB (`maxXzDictionary`, above the 64 MiB of `xz -9`); data that needs
more fails with an error that satisfies `errors.Is(err, xz.ErrTooLarge)`.
`ulikunitz/xz` remains in `go.mod` only for the tests that build `.xz`
fixtures (encode side).

## What gets verified

With `ZPKG_VERIFY` on — the default — **every** pull that brings bytes onto
the machine checks the artifact's cosign signatures against the configured
trust set and fails closed. Not "every install": every pull.

That distinction is the whole of it, and it has been got wrong twice. The
first time, the check lived in `DownloadArtifact`, which only the mirror
tooling calls, so `zpkgx` and `zpkgm` installed unsigned artifacts while
advertising otherwise. The second time was the **catalogue** — the list of
project names `zpkgs ls` and `<TAB>` read — which was fetched past the check
because it is "only a list of names".

A list of names is what a person then types. Forging it does not get an
unsigned artifact installed, because the install path still verifies; it gets
a near-miss name offered at the prompt, which is the whole of a typosquat.
And since that catalogue is now fetched once and read from disk for days,
it is verified *less* often than an artifact, not more — so the one check it
gets has to happen.

The rule, for anything added later: if it pulls bytes, it goes through
`verifyPulled`, whatever it means to do with them. The store cache is no
exception: a cache hit is re-checked against the signatures the registry
advertises, because a cache is an optimisation and never an authority.

## Who may vouch, and how many of them

Verification is against a **trust set**, not a single key: TUF's shape (a set
of keys and a *threshold* of them) with Nix's spelling for the list.

| variable | what it does |
| --- | --- |
| `ZPKG_TRUSTED_KEYS` | **replaces** the trust set — `name:KEY`, whitespace separated |
| `ZPKG_EXTRA_TRUSTED_KEYS` | **adds** to it, which is usually what you want |
| `ZPKG_TRUST_THRESHOLD` | how many *distinct* trusted keys must have signed (default `1`) |

```
ZPKG_EXTRA_TRUSTED_KEYS='alice:RWQ…' ZPKG_TRUST_THRESHOLD=2 zpkgx +fftw.org
```

Two people building the same inputs get the **same** hash — deliberately, and
that collision is the evidence. What tells them apart is the *attestation*:
each attaches their own signature referrer to the one artifact, and the client
counts how many distinct trusted keys it can verify. A threshold of 2 means
"I install nothing that two builders did not independently reproduce".

Three rules this hangs on:

- **Each key counts once** (TUF §5.4.2). Otherwise a threshold of two is met
  by pushing one signature twice, which anyone who can push can do.
- **A signature from outside the trust set is not an error.** Anybody may sign
  a public artefact; if a stranger's signature invalidated an artifact,
  invalidating any artifact would cost one push. It is counted and ignored.
- **A threshold nobody could meet is refused when the configuration is read**,
  not at install time, because that mistake is in the configuration and a
  message about the artifact would send you looking in the wrong place.

The signer name you see comes from **your** trust set and never from the
registry: a name on the artefact is written by whoever pushed it. The referrer
carries only a key id, which is checkable, and which is used to pick which key
to try first — never to decide which may succeed.

## Rotating a key, and revoking one

Three states, and the difference between the last two is the whole reason
there are two lists:

| | signs | counts towards the threshold | reported as |
| --- | --- | --- | --- |
| `SigningPublicKey` — **current** | yes | yes | its name |
| `RetiredSigningPublicKeys` — **retired** | no | **yes** | its name |
| `RevokedSigningKeys` — **revoked** | no | **no** | named, with the reason |

**Retiring** is changing the key you sign *with*. It says nothing about what
is already signed, so a retired key stays in the trust set and nothing needs
re-signing. Rotation is an edit to two variables: the new key goes up, the old
one moves down.

This has happened once, on **2026-11-06**:

| key id | state | what it signed |
| --- | --- | --- |
| `df35c3a46931d3e6` | current | everything from 2026-11-06 |
| `3eae61fe7d7cb689` | retired, as `go-zpkg-until-2026-11` | every artifact before it |

⛔ **Retired and not revoked, which was a judgement and not a finding.** The
old key's private half could not be located — two scans of the maintainer's
workstation covered 2,167,120 files, and what sat in the CI secret turned out
to be its *public* half. **Lost is not compromised**: nothing suggests anybody
else holds it, so everything it signed stays trusted and nothing is rebuilt.
If evidence of compromise ever appears it moves to `RevokedSigningKeys`, and
then it does.

`rotation_test.go` pins both key ids as literals, so neither variable can
change without a test saying so.

And a retired key is **not discounted**: an artifact signed by the current key
and a retired one counts as *two*. That is exactly right during an overlap,
where the publisher deliberately signs with both — a scheme that ranked
retired keys lower would make a threshold of 2 unmeetable precisely while
rotating.

**Revoking** is saying somebody else may hold the key. Nothing it signed can
be told from a forgery, so its signatures count for nothing — including on
artifacts it signed legitimately before the compromise.

⛔ **And they cannot be told apart by date, because there is no date.** Every
published artifact carries the same pinned timestamp so that a re-publish is
byte-identical, so *"was this signed before the key leaked?"* has no answer on
the artefact. Honouring signatures made "before" a revocation would be a check
that cannot fail — and it would restore trust in exactly the artefacts an
attacker would plant. Whether to buy that distinction with a third-party
timestamp is
[artifact#215](https://github.com/go-zpkg/artifact/issues/215).

A revoked signature is reported **as itself**, not folded into "signed by an
untrusted key". A stranger's signature is noise anybody can make; your own
revoked key on an artifact is a fact about your supply chain. Every entry carries
a `Because`, because a revocation without a reason is a rumour.

## What a project NAME may be

A name is a name. It is not a path and it is not a URL fragment — and it
reached one anyway, because every lookup builds a URL by concatenation:

```go
fmt.Sprintf("%s/%s/%s", base, project, "package.yml")
```

Go sends a request path **verbatim** — it does not clean `..` — and
`raw.githubusercontent.com` answers a traversing path with a **307** to the
normalised one, which Go's client follows. Measured, not reasoned about:

```
httpGet(".../pkgxdev/pantry/main/projects/../../../../go-zpkg/pantry-overlay/main/README.md")
→ 1270 bytes of ANOTHER repository's file
```

A recipe is not inert. It declares dependencies, a build script and the
runtime environment a package exports, so fetching one from a repository an
attacker chose is the whole game.

The check is where the name is **used** — the HTTP pantry lookup, the OCI
reference, `ParseLock`, `UnmarshalCatalog` — because hardly any of these
names were typed. They arrive in a **lock** fetched from a repository, in a
**catalogue** pulled from a registry and read by every `<TAB>`, and in the
dependency lists inside both. One forged name refuses the whole lock or
catalogue: a hostile member means the list was written to be one.

An **allowlist**, not a list of dangerous spellings — `..` is obvious,
`..%2f` is not, and the probe showed it reaching a different path. Segments
of `[A-Za-z0-9._+-]`, at most 8, at most 200 characters. All 1908 published
projects fit; the deepest is four segments
(`github.com/GoogleContainerTools/container-structure-test`), and that list
is the test's positive control, because a rule tightened too far refuses
everything and reports green.

## A version can carry a rebuild counter

`1.8.2_1` is the **same upstream software** as `1.8.2`, built again — for a
compiler security release, say, where nothing about the recipe or the version
changes and the binary does.

Absent means **0**. That is Debian's rule for its own revision (*"the absence
of a debian_revision is equivalent to a debian_revision of 0"*) and, here, the
literal state of the registry: measured 2026-10-10, **0 of 1371** published
version strings carry one, and the only non-alphanumeric rune among them is
`.`.

⛔ **Before this, a rebuild was invisible and an exact pin lied about it.**
`ParseVer` stops each component at the first non-digit, so `1.8.2_1` and
`1.8.2` both yielded `Nums [1 8 2]` and compared **equal**:

```
1.8.2   satisfies "=1.8.2_1" ? true
1.8.2_1 satisfies "=1.8.2"   ? true
```

A lock pinning the rebuilt artifact would have installed the un-rebuilt one — the
vulnerable one, since a rebuild is what a toolchain security fix produces — and
said nothing. `satisfies` routes every operator through one comparator, so
ordering and exactness were the same fix.

It orders **numerically**, and a real version bump still dominates any number
of rebuilds below it:

```
1.8.2 < 1.8.2_1 < 1.8.2_2 < 1.8.2_10 < 1.8.3
```

### ⛔ And it has no shorter spelling

`tagSpellings` offers `1.2.0` as another way of writing `1.2`, because a
trailing zero really is the same release. It built those alternatives from the
numeric components alone — and the rebuild counter is not one of them, so
`3.3.11_1` used to offer **`3.3.11`**, which is not another spelling of it but
the build it supersedes.

`PublishedTagFor` walks these and asks the registry about each, so a lock
pinning the rebuilt artifact was answered "published" on finding the un-rebuilt
one, and a catalogue would advertise a rebuild that does not exist. That is
the same defect as the comparator's, by a second route, and the same one the
non-zero rule already guards against for neighbouring releases — *26.8.1 must
not suggest 26.8.0*.

A rebuild now has exactly one spelling: its own.

### ⛔ And it does not delete the build it supersedes

The same cause, by a third route. `numericKey` gives a version its canonical
identity so that `2.44` and `2.44.0` — one release, two tags, and our registry
carries both — collapse into one candidate instead of letting the registry's
listing order decide. It too was built from the numeric components alone, so
`3.3.11` and `3.3.11_1` shared the key `3.3.11`, and `selectVersions` kept one
and **dropped the other from the listing entirely**.

Measured against `ghcr.io/go-zpkg/packages/fftw.org`, which publishes both
tags:

```
VersionsFor(fftw.org) = 3.3.11_1          # 3.3.11 is published, and absent
=3.3.11  darwin/aarch64 -> (nothing)      # the artifact is there, and pullable
```

So **rebuilding an artifact silently broke every lock that pinned the version it
rebuilt** — the exact mirror of the comparator defect, where a pin on the
rebuilt artifact was satisfied by the un-rebuilt, vulnerable one. With three
builds of one version the listing kept only the last: `1.8.2`, `1.8.2_1` and
`1.8.2_2` all answered `1.8.2_2`.

Superseding is a question of **order**, which `cmpVer` answers, not a licence
to delete the loser. The counter now joins the key, so the newest is still the
rebuild and every published build stays pinnable. Two *spellings* of one build
still collapse — `3.3.11_1` and `v3.3.11_1` are one artifact — which is what the
key is for.

### ⛔ pkgx cannot read a `_N` tag, and that is a deliberate trade

`_N` follows Homebrew's `rebuild` and Debian's `+bN`, and **pkgx/libpkgx
cannot parse it at all**. Its `SemVer` constructor
(`src/utils/semver.ts:26-41`, read 2026-11-02) splits on `.` and accepts a
part only if it matches `/^(\d+)([a-z])$/` — last part only — or `/^\d+$/`,
and otherwise throws `invalid version`. For `3.3.11_1` the parts are `3`, `3`,
`11_1`; the third matches neither.

So **pointing a pkgx client at this registry is not a supported
configuration** once a project carries a rebuild. It throws rather than
resolving the wrong artifact, which is the better of the two failures, but it is
a failure.

The alternatives were weighed and rejected: a fourth numeric component
(`3.3.11.1`) parses in pkgx but cannot be told apart from a genuine
four-component release such as ghc `5.64.3.2`; a letter suffix (`3.3.11a`)
parses in pkgx but caps at 26 and occupies the slot real versions use, as
openssl's `1.1.1w` does. Build metadata (`+neon`) is not an option at all —
the OCI distribution spec requires a tag to match
`[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}`, which excludes `+`.

### An underscore is not always a rebuild

`_` is admitted by `ValidateVersionString` because it is ordinary in versions
elsewhere, so `2026_09_25` is a shape this parser can meet — and reading its
`_25` as a rebuild would turn one release into the 25th build of another.

The rule is that the part **before** the underscore must be dotted. Every
version this registry carries is; a date-like one is not. `_beta` is not a
rebuild either: what follows must be all digits. And it splits at the **last**
underscore, so in `1.0_2_3` the version is `1.0_2` and the rebuild is 3 —
zbk appends `_N` to a version it already resolved.

## An end-of-life line is ranked last, never removed

`ZPKG_DEPRECATED` may name a JSON file of end-of-life release lines per
project, e.g. `{"openssl.org": ["3.6", "3.4"]}`. Among the versions that
satisfy a constraint, one on a listed line is chosen only when nothing else
satisfies, and the fall back is announced on stderr
(`PickVersionForAllWarn` returns the warning as data). So `^3` resolves to
3.5.8 while `^3.6.4`, `=3.6.4` and a lock still resolve to 3.6.4: it is a
**rank**, not a filter, and it never reaches across a soname boundary (`^3`
and `^4` share no satisfier). The list is read locally; the resolver never
needs the network to choose.

A binary may also carry a default, `DefaultDeprecated`, set before the first
resolution — because an opt-in variable fixes nothing: with the variable as
the only source, this feature changed no answer for anybody, and openssl's
3.6 line went end-of-life with `^3` still resolving to 3.6.4 everywhere.
`zpkgx` sets it from an embedded, dated list.

The precedence is deliberate, and the surprising direction is the one to
avoid:

| `ZPKG_DEPRECATED` | list used |
| --- | --- |
| set, readable | that file, and **only** that file — never a union with the default |
| set, missing or unparsable | **empty, with a warning** — explicitly *not* the default |
| unset | `DefaultDeprecated` |
| unset, and no default | no list, i.e. the behaviour without this feature |

An operator who names a file has said what they want; quietly substituting
the default for an unreadable one would hide their mistake behind behaviour
that looks like it worked.

## The lock format lives here

`zbk lock` wrote locks and nothing could read one back, because the reader
was in zbk's `package main` — importable by nothing. A format with exactly
one program able to read it has not left the program it was written for,
and the whole point of a lock is that something **else** acts on it later.

So the format is here — `Lock`, `LockPin`, `RenderLock`, `ParseLock`,
`ReadLock`, `LockAge` — and the **resolution** stays in zbk, which is the
real seam: deciding what a set means today needs a pantry, an overrides set
and a version resolver; reading a file that records the answer needs none
of them. Writing moved with reading, because a format whose two ends live
in different repositories is a round trip waiting to break on a field one
side forgot.

The version rule is Spack's: new readers read old locks, old readers refuse
new ones.

## A recipe can declare a service

A daemon's recipe says how to run it as a service, as data, in one
`service "<name>" { … }` block in its `package.hcl`. `ParseService` reads
it and `FetchService` fetches it (overlay first, then the base pantry); the
installer renders the unit from it, so the hardening every service shares is
written once and a recipe states only what differs:

```hcl
service "authn-bridge" {
  description   = "authn-bridge, an OpenID Connect provider in front of a SAML federation"
  command       = "authn-bridge"                  # a program in bin/, never a path
  args          = ["--config", "/etc/authn-bridge"]
  stop-timeout  = "20s"
  state-directory { mode = "0700" }               # /var/lib/authn-bridge
  runtime-directory { mode = "0700" }             # /run/authn-bridge
  configuration-directory { mode = "0750" }       # /etc/authn-bridge
}
```

Also `user` (default: the name), `capabilities` (default: none), `restart`
(`on-failure` | `always`), `reload` (`none` | `hup`), `proc-subset` (`pid` |
`all`) and `documentation`. The fields are the ones that varied between three
real daemons (go-authn's authnd, authn-bridge and authn-revokd), nothing more.

**Readers before this version are not broken by it**, which was measured
rather than assumed: the recipe reader is a generic one, so the block is one
more key every consumer ignores — `FetchMeta` returns the same dependencies
and provides with it as without it, and `zbk lint` passes. That reader drops
the block's **label**, though, so two `service` blocks are a duplicate key to
it and the whole recipe becomes unreadable for every older client. Hence one
service per recipe, refused here as well.

The block itself is strict: an unknown attribute is refused rather than
ignored, because a misspelt `capabilites` would otherwise render a unit
without the capability. Arguments are a closed alphabet (letters, digits,
`_ . / : = , @ + -`), because they are written into a unit that root loads,
where a newline is a new directive and `%`, `$`, quotes and `;` all mean
something.

## "It is not here" is two states, and both are types

A caller that wants to offer a next step — *ask for this to be published* —
cannot act on prose, so the two ways a project can be unavailable each have
a type:

| | |
|---|---|
| `*NotPublishedError` | the registry does not carry the project **at all**. ghcr spells this as `403: denied` at the token endpoint for a repository that does not exist, which reads as a credentials fault and is not one |
| `*NoArtifactHereError` | the project is published, just not for **your** platform. It carries the versions that exist and the ones with no artifact, so the message stays the sentence the field reports settled on |

`ProjectToRequest(err)` answers both with the project's name, and `""` for
everything else. One call, because two predicates at the call site is how
one of them comes to be forgotten — which is what happened:
`*NotPublishedError` alone covers the *rare* half. Measured against the
published `darwin/aarch64` catalogue on 2026-10-23, **567 of 1940 projects**
had a recipe and no artifact, and for the length of one release
`zpkgx`'s "you can ask for this" hint could not see any of them.

⛔ The prose predicate that preceded them is still here as
`IsNotPublished`'s last resort, and it is **too wide once it leaves this
package**: it matches `not found` anywhere in a message, and its first use
outside fired on `command not found in the requested packages: true`, where
the package was published and the *command* was missing.

## A closure can be completed for a platform you are not on

`CompleteClosure` resolves a package's declared closure, installs it, then
reads the artifacts' own `DT_NEEDED` (or Mach-O load commands) and pulls
whatever provides each unsatisfied soname — the implicit glibc/gcc
libraries and the undeclared ones that `package.yml` graphs omit — until
the closure is complete enough to run on a `FROM scratch` image.

**`CompleteClosureFor` does that for an explicit `os/arch`**, so one
machine can audit all of them:

```go
closure, err := artifact.CompleteClosureFor(roots, dir, "linux", "x86-64")
```

⛔ **Why it had to exist.** `zbk unresolved` reports every reference an
installed closure cannot answer; wired into CI it found **967
unresolvable references over 259 of 1407 packaged projects** on
linux/x86-64. The other five platforms had never been asked, because this
function resolved and installed for the host and nothing else could be
said honestly — the same shape as a CVE lane that scanned two platforms
of six for two months.

⛔ **The target's OS picks the binary format**, and that is the only line
of it that is a behaviour change rather than a pass-through to
`ResolveClosureFor` and `InstallFor`. Reading a linux closure from a mac
has to take the ELF path; taking the host's would complete nothing, find
every soname satisfied *because it never looked*, and report a clean
closure — a wrong answer that looks like good news. Two tests pin it in
both directions, and `CompleteClosure` is now exactly
`CompleteClosureFor(…, HostSlug())`, so the host path is identical by
construction rather than by a second reading of the same logic.

⛔ **A load command is input from a stranger.** The `@rpath` references this
reads come out of artifacts that were *downloaded*, and both halves of one go
somewhere: the reference becomes the path that is stat'd to decide a reference
is already satisfied, and the project it names becomes a registry repository
and a store path **written to** (`<dir>/<project>/v<version>`). Since v0.58.0
a reference that does not stay inside the store (`filepath.IsLocal`) and a
project that is not a usable name (`ValidateProjectName`) are both refused —
and both refusals are *said*, because a silent skip is the failure this code
already paid for once at 1266 references. Without the first, an artifact naming
`@rpath/../../../../etc/passwd` had that reference passed over as "satisfied"
on the strength of a file that is neither a library nor in the store.

`FuzzMachoRef` holds the invariant over arbitrary input; its committed corpus
includes `@rpath/..0`, which refuted the first version of the test's own
assertion in 0.16s — `..0` is an ordinary filename, and a hand-rolled
re-derivation of `IsLocal` was wrong where `IsLocal` was right.

⛔ **And since v0.59.0 `InstallFor` checks the name it writes under.** It
builds `<pkgxDir>/<project>/v<version>`, and was safe only by *order*: the
fetch below it goes through `OCIClient.repository`, which validates. But the
`os.Stat` deciding "already present" runs first, so a project of `../x`
naming a directory that exists returned `(false, nil)` — this function's way
of saying *already installed*. The caller was told the work was done, nothing
was installed, and the evidence was a directory outside the store. `Resolved`
is an exported struct with exported fields, so a caller can fill it without
passing through a resolver or a catalogue; the order of two unrelated checks
inside one function is not a boundary. Measured before adding it: the
pantry's 1929 recipes carry 6381 dependency keys and every one
passes, so it rejects nothing that exists.

## Where it is proven to work

This package reads formats it did not write — ELF and Mach-O headers, OCI
manifests, tar and xz streams — every one of them little-endian on the wire. So
any place that reads an integer through the host's byte order rather than
through `encoding/binary` is wrong on a big-endian machine and nowhere else,
and a compiler cannot see it. CI therefore does not stop at cross-compiling: it
**runs the suite** on seven runtimes that are not the host.

| lane | how |
| --- | --- |
| `test (arm64\|riscv64\|ppc64le\|s390x\|loong64, qemu)` | `go test -exec qemu-<arch>-static`, `-count=1` so a cached PASS from the host architecture cannot stand in for a run that never happened |
| `test (js/wasm, node)` | node 24. Go's js/wasm port takes `net/http` through the host's `fetch()` and the filesystem through the host's `fs` — two runtimes no other lane exercises. A browser that installs a signed artifact into its own store runs this code |
| `test (wasip1/wasm, wasmtime)` | a *different* wasm port with a different syscall surface: no network at all, and a filesystem only where one is granted. A package that installs artifacts has to know which of the two it is on |

An artifact for the `wasip1/wasm` platform is published with the OCI platform
`os=wasip1, architecture=wasm` (the Docker+Wasm / CNCF wasm-oci-artifact
spelling; only `x86-64` and `aarch64` are renamed), and a recipe may scope a
block to `wasip1:`, `windows:` or `js:` without it being read as a plain value
on another host.

`s390x` is in the list because it is big-endian and nothing else here is. The
build matrix adds linux/darwin on amd64 and arm64 and both wasm targets, so
everything that runs also compiles with `CGO_ENABLED=0`.

BSD-3-Clause.
