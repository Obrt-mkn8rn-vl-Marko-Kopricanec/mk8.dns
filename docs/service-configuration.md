# Installation-local service configuration

Application, Gateway and Operator take no command-line service values or bootstrap
locators. Each independent build or publish root loads exactly one awaited
`SupprocomSecretFileStore.LoadAsync` startup snapshot from
`AppContext.BaseDirectory/Environment/.env`. The pinned public NuGet dependency is
Supprocom.Secrets **0.1.4**. Its package metadata identifies source commit
`56b796072c54e203ce975ffc5b3f17862ad0496a`; this is not a claim of equality with a
separate local checkout or vendor authenticity.

The loader explicitly selects Production, `FileOverridesProcessEnvironment=true`,
`Import=None`, `Recovery=None`, and `InstallationBoundAesGcm` with the built-in
`.installation.key`. It does not add process environment, default host settings,
appsettings files, legacy JSON files, external pointers/manifests/adapters or
credential/key files as service-value authorities. The builtin active and template
names are both fixed to `.env`: a separate `.env.template` is never an acquisition
source, including when active input is empty or lost. Initially absent active input
is refused before builtin acquisition; empty active input is refused by the pinned
builtin template validation against that same empty active path. The package still
owns its normal protection/key writes for valid active input. This is not a
certificate against arbitrary concurrent filesystem replacement or compromised
installation custody. Web hosts use the empty builder with explicit Kestrel/routing and Production;
no default JSON/environment providers are constructed. The single in-memory
framework source holds the fixed hosting-startup prevention guard only;
service values are consumed exclusively from the typed package snapshot. Publishing copies nonsecret
`.env.template` guides only, never active documents or installation keys.

Provision active documents through Supprocom.Secrets under the installation's
independent custody gates. Do not put active documents, keys, credentials or their
values in Git, diagnostics or retained development evidence. This change does
not provision keys, databases, endpoints, journals, trust anchors or independent
revision floors.

## Role collections

One document contains one role prefix: `Application:`, `Gateway:` or `Operator:`
(the package also normalizes dotenv `__` to `:`). Unknown role keys, absent required
values, duplicate structured fields and malformed encodings fail startup. A
reference is the name of another value in that same collection, never a file path
or external provider location. Binary values use base64; publication identity PEM
and database connection strings are same-collection text values. Owned management credential arrays are cleared only after operation and transaction
settlement, including failure; caller ingress buffers remain borrowed. Other mutable
startup copies follow their declared ownership lifetime. Immutable snapshot strings,
transport buffers, serializer copies and runtime/provider internals are not claimed
to be erased.

`Settings` is a JSON array of the closed existing option/value vocabulary, stored
inside the role collection. It is data from the one snapshot, not actual command
arguments or a CLI configuration provider. The legacy pure settings parsers remain
library compatibility APIs; executables never use them to load files or accept
CLI service values.

Application requires `Mode`: `authority`, `recursive`, `recursive-refresh` or
`recursive-checking-disabled`. Authority Settings require socket, state directory,
node identity and role. Control/cookie/TSIG references are `--control-secret`,
`--cookie-secret`, `--tsig-secret`; their old file options are refused. Serving
replicas explicitly supply every UDP budget, a cookie secret and `TsigMode`
(`enabled` or `disabled`). `Control` is a closed structured collection value with
all fields supplied, including explicit nullable/disabled fields. Its zones and
grants explicitly supply signing policy, dispatch interval, actions and scopes; no service-level
signing/grant default fills missing input.

Recursive modes require `Recursive` and its declared `keySecret`. Their closed
fields and ownership/trust assumptions are documented in
[recursive startup](development/recursive-executable.md). These modes open existing
journals only and do not initialize or maintain independent trusted floors.

Gateway Settings explicitly select `--role query` or `--role management` and their
corresponding endpoints. Application authority and Gateway also require a complete
`HostPolicy` JSON value with `ShutdownSeconds`, `HeaderBytes`, `HeaderCount`,
`RequestLineBytes`, `HeaderTimeoutSeconds`, `Connections`, `ApplicationStreams`,
`PublicationStreams`. Explicit values may tighten the inherited software ceilings;
these limits do not promise resource capacity or shutdown progress.

Operator Settings select `--socket` or `--gateway-socket`, `--request-secret` and
`--credential-secret`, with their values. The request is same-collection structured
text and the credential is exactly 32 decoded bytes. Existing authenticated RPC
and management authorization contracts remain in force.

## Development and publication

Use the ordinary .NET build, `dotnet publish` and `dotnet run` mechanisms. Do not
add OS configuration, systemd, Debian or package-maintainer bootstrap integration.
Separate role outputs remain independent. Test-only fixture entry points can
select task-owned roots; no public loader exposes a locator. Child integration
hosts run from private copied role roots with task-owned documents and no service
arguments. Those documents and keys are deleted only after their owned children
settle, and are excluded from retained packets.

This source contract grants no installation, runtime, publication, deployment or
operational acceptance. Names, addresses, accounts, certificates, secondary
provisioning and topology remain owner inputs subject to their existing gates.
The Monday 12 October noon Europe/Zagreb deadline is never a gate waiver.
