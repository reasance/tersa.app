<!--
This Source Code Form is subject to the terms of the Mozilla Public License,
v. 2.0. If a copy of the MPL was not distributed with this file, You can obtain
one at https://mozilla.org/MPL/2.0/.
-->

# ADR 0029: Safe content and composition boundaries

- Status: Accepted; rendering and composition amended by
  [ADR 0031](adr-0031-tui-only-pivot.md)
- Date: 2026-08-29

## Current implementation and scope

Received MIME/HTML, links, filenames, attachments, and editor input are untrusted.
The terminal client implements bounded MIME decoding, HTML-to-text conversion,
and `SafeText` sanitization in `tersa-presentation`. It does not implement a rich
editor, image fetcher, process sandbox, or trusted HTML round trip. Composition
is future T5 work through `$EDITOR`; see
[ADR 0028](adr-0028-drafts-outbox-and-idempotent-send.md).

## Received-content boundary

Only presentation types may construct terminal-safe received content. Domain
and application crates remain free of renderer and OS types. Headers, addresses,
body text, links, labels, and filenames are sanitized before terminal output;
raw MIME/HTML stays untrusted even inside encrypted SQLCipher.

Parse/decode/conversion must bound input bytes, nesting, parts, and output.
The earlier accepted hardening ceilings remain requirements for any richer
parser extension: 32 MiB raw MIME, 16 multipart levels, 1,024 parts, 256 KiB
per text block, 50,000 render nodes, and two seconds of parse CPU time. These
are planning ceilings, not a claim that every limit is enforced by the current
terminal converter; implemented limits live in the presentation code. Unsupported or malformed content degrades to safe text or a closed
content-unavailable result, never a partially trusted HTML/terminal stream.
Scripts, event handlers, forms, frames, CSS URLs, embedded objects, executable
data URLs, and control sequences cannot create terminal actions. No renderer
may parse content with wider filesystem, credential, or network authority as a
fallback after a limit or validation failure.

The sanitizer removes terminal control and invisible formatting characters as
specified in ADR 0031. HTML conversion emits text; it does not authenticate links
or senders. Confusable scripts and homoglyphs remain residual risks. Fuzzing is a
required future assurance surface; deterministic randomized tests are not a
claim that fuzz targets already exist.

## Remote content and links

No remote resource referenced by a message is ever fetched. Tracking images,
stylesheets, fonts, and embedded content stay inert; there is no sender-permission
exception or background fetch route. A future change to this closed boundary
requires a new accepted ADR, data-flow/threat-model update, and explicit consent
and transport-security design before implementation.

Links may open only after an explicit user action shows the destination. They
must use a validated argument vector, never shell interpolation. Parse/layout
never opens, downloads, or executes a resource. ADR 0031 defines this planned
link behavior; current completion is recorded in the
[threat model](../security/threat-model.md).

## Composition and MIME

The planned terminal editor uses an owner-only temporary file; Rust validates
editor output before durable draft storage or MIME construction. Editor-created
swap/backup files and privileged local processes remain outside this guarantee.
Received content is never trusted merely because it is pasted into a draft.

The MIME compiler consumes a bounded validated compose representation, recipient
values, and account-bound attachment references. It deterministically serializes
complete MIME before dispatch, with the ADR 0028 encoded-size/digest/revision
binding. Raw editor HTML cannot bypass this boundary. Any later structured
formatting model must be a closed AST with allowed paragraph/list/quote/code/link
and attachment references and deterministic plain/limited-HTML serialization;
it requires a separate reviewed extension beyond the plain-text terminal MVP.
Outbound generated HTML would not be a received-content renderer or a trusted
input channel.

## Routing, lock, and failure handling

Every asynchronous render/composition result is tied to AccountId, message or
draft route, generation, and cancellation state. Account switch, cancellation,
or lock rejects stale results before publication. Planned app lock also closes
stores and evicts models/keys under ADR 0030; documentation does not implement it.
Attachments remain on-demand, size-bounded, and never auto-opened. Save/Open is
explicit user-directed declassification; no hostile document preview is implied.

Malformed input retains the last valid draft rather than partially serializing
unchecked content. Failures expose closed redacted categories without raw HTML,
MIME, addresses, URLs, or secrets in diagnostics. A unified view never changes
an attachment, draft, or content result's account binding.

## Required verification and non-claims

Hostile fixtures and property/fuzz checks must cover MIME framing, encodings,
limits, malformed HTML, terminal controls, link schemes, cancellation, stale
account/generation, and deterministic compose serialization. TUI checks must
exercise sanitized rendering and explicit-action boundaries; editor and attachment
flows need their own acceptance evidence when implemented.

No source test certifies a hostile-content process sandbox, general browser,
remote-image transport, document preview, sender identity, live send, or release.
The [security data flow](../security/data-flow.md) and
[threat model](../security/threat-model.md) record implemented versus planned flows.
