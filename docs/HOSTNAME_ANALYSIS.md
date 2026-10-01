# Hostname analysis

`names <host...> [--json]` performs a local string analysis. The same matcher
is used for the target hostname and collected TLS certificate CN/SAN values.
It makes no DNS, HTTP, CT or packet-capture requests. It does not infer a name
from an IP address, enumerate subdomains or verify domain ownership.

## Meaning of a finding

`strong` means a distinctive name such as `amneziawg`, `vless` or `marzban`.
`moderate` includes ambiguous conventions such as `vpn`, `sub`, `panel` and
`subscription`. `weak` includes broader associations. These are manually
chosen naming tiers, not calibrated probabilities or measured precision.
Documentation sites, corporate access systems and unrelated services can match.
No tier changes the full scan score or any TSPU rule.

Each finding has a `kind`:

| Kind | Interpretation |
| --- | --- |
| `token` | a protocol, product or naming word occurs in a label |
| `provider_domain` | the name is within a documented provider zone |
| `provider_node` | the zone and a supported node naming pattern match |
| `hosting_domain` | shared application hosting, not VPN evidence |

The `sources` array retains `target`, `cert_cn:port` and `cert_san:port`.
Case and the final root dot are normalized before deduplication. Wildcard
certificate names remain distinct from the apex. Certificate names may belong
to a cover site or a different service, including on another TLS port.
This feature does not check whether any name was published in certificate logs.

## Matching and input limits

Names are limited to 253 ASCII bytes, plus an optional final root dot; each
label is limited to 63 bytes. One leading `*.` wildcard and underscores in
DNS service labels are accepted. URLs, host:port strings, empty labels,
embedded wildcards, controls and invalid lengths produce errors.
IP literals are reported as not applicable. No reverse lookup is attempted.

Generic tokens match complete hyphen/underscore-separated components, with
optional numeric suffixes. The longest known token wins (`socks5001` matches
`socks5`, not both `socks5` and `socks`). `wg01`, `awg2` and `sub2` match;
`subaru`, `vpnews` and `clashroyale` do not. Distinctive software names may
match anywhere within a label, which can still produce false positives.

Punycode labels are decoded using the bounded algorithm in
[RFC 3492 section 6.2](https://www.rfc-editor.org/rfc/rfc3492#section-6.2)
before matching. Output includes both `label` and `decoded_label`.
The table includes lowercase Russian `впн` and `подписка`. This is not a full
IDNA/UTS #46 implementation: supply canonical ASCII/Punycode names. Raw Unicode
input is rejected with an explicit instruction; no Unicode case folding,
homoglyph matching or transliteration is performed. Unsupported control,
separator and invalid scalar encodings are rejected.

## Public suffix data

The [Public Suffix List](https://publicsuffix.org/list/) determines which labels
are outside the registrant's naming control. Its ICANN and PRIVATE sections,
wildcards and exceptions are included. Tokens in suffix labels are skipped.
Unknown suffixes use the PSL default `*`; this fallback is not ownership proof.

- Snapshot version: `2026-09-08_12-18-37_UTC`
- Upstream commit from the snapshot: `3955e3ec29b94c3cca7bd4509c5f14a7c0959e26`
- Original bytes SHA-256: `4b673689999dbaca60b93fa3e1da5752505ef9717b1c4dc44acbfdafd35679ea`
- Original and license: `third_party/psl/`
- Embedded rules: `src/scan/public_suffix_data.inc`

Refresh explicitly with `python tools/update_public_suffix.py`. The generator
downloads from the official distribution URL, converts Unicode labels to
Punycode and embeds a sorted table. `--source path` uses a local snapshot;
`--check` verifies the checked-in table without network access. Update the
snapshot metadata above when refreshing. Runtime scanning never downloads it.

## Provider rules and primary sources

These rules describe naming patterns, not a current inventory of active nodes.
All suffix comparisons require a dot boundary: `notnordvpn.com` and
`de1.nordvpn.com.example` do not match NordVPN's zone. A provider's apex,
website or API yields only a weak domain association, not a node finding.

| Zone | Supported node pattern / source |
| --- | --- |
| `mullvad.net` | `cc-city-wg[-socks5]-number.relays.mullvad.net`; [Mullvad documentation](https://mullvad.net/en/help/different-entryexit-node-using-wireguard-and-socks5-proxy) |
| `ivpn.net` | a location label under `wg.ivpn.net`; [IVPN setup example](https://www.ivpn.net/setup/router/pfsense-wireguard/) |
| `nordvpn.com` | two letters followed by digits, directly under the zone; [NordVPN server naming example](https://support.nordvpn.com/hc/nl/articles/19646487549585-Hoe-vind-ik-de-naam-of-het-adres-van-de-server-van-VPN) |
| `cloudflareclient.com` | domain association only; [Cloudflare service policies](https://developers.cloudflare.com/cloudflare-one/traffic-policies/global-policies/) |
| `workers.dev` | hosting association only; [Cloudflare Workers routing](https://developers.cloudflare.com/workers/configuration/routing/workers-dev/) |

Other provider naming patterns are not exhaustively covered. A generic `de1`
or `ch-30` outside a supported provider zone is not sufficient evidence.

## JSON and exit codes

The offline report contains `protocol_confirmed: false`, `network_checked: false`
and `score_impact: 0`. Each result has a `status` of `hostname`, `ip_literal` or
`invalid`, plus counts and marks. Invalid input has a per-result error.
Full scan JSON retains `hostname_marks`, with source and kind fields, and adds
`hostname_protocol_confirmed: false` and `hostname_score_impact: 0`.

Exit codes are 3 for any strong mark, 2 for any moderate mark, and 0 for only
weak marks, no matches or IP inputs. Missing/invalid input takes precedence
and returns 64, while still reporting all supplied inputs. These codes describe
name analysis, not connection safety, reachability or protocol identification.

## Validation

Unit regressions cover suffix exceptions/private zones, numeric suffixes,
canonical deduplication, certificate provenance, malformed input, Punycode and
provider suffix spoofing. `python tests/test_names_cli.py ./byebyevpn.exe`
checks the command, JSON and exit codes against a built binary.

No real-traffic accuracy estimate follows from these tests. AWG packet analysis
remains a separate [PCAP/PCAPNG heuristic](AMNEZIAWG_ANALYSIS.md); silence from
an unauthenticated UDP probe does not confirm or rule out an AWG listener.
