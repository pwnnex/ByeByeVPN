# TLS, HTTP and CT observations

The scanner reports what a peer returned to unauthenticated probes. Certificate
age, validity period and self-signature status, HTTP error pages and silence do
not identify a VPN protocol. These observations no longer lower the heuristic
score or add TSPU rules. Other heuristics, including SNI routing and brand/ASN
comparisons, remain in the legacy model; its thresholds have not been calibrated
against a labelled dataset or a real operator classifier.

## Certificates

`inspect_certificate()` reads the leaf certificate independently of network I/O.
Matching subject and issuer names set `self_issued`. `self_signed` additionally
requires the certificate signature to verify with the leaf's own public key.
This is a signature check, not trust-chain or hostname validation. See
[OpenSSL X509_verify](https://docs.openssl.org/3.6/man3/X509_verify/).

Validity calculations use seconds. A certificate that expired an hour ago is
expired even when the rounded display still says zero days left. Invalid or
reversed ASN.1 validity times set `certificate_times_valid` to false. Numerical
time fields are meaningful only when that flag is true. `certificate_expired`
and `certificate_not_yet_valid` use the scan's local clock.

Short validity and recent issuance are informational. Let's Encrypt offers
public short-lived certificates with a 160-hour validity period; replacing them
with a longer-lived certificate is not a VPN detection fix. See the
[availability announcement](https://letsencrypt.org/2026/01/15/6day-and-ip-general-availability).

`is_letsencrypt` means the issuer organization field says `Let's Encrypt`; it
does not authenticate the issuer. DNS SANs and CNs are retained with their
source for hostname analysis. An empty DNS SAN list does not imply that the
certificate has no other SAN types.

## HTTPS responses

The probe offers HTTP/1.1 over TLS, checks that its request was written, and
collects up to 16 KiB of response headers. Reading is not limited to a fixed
number of TLS records. Nonblocking TLS I/O gives the request write and response
read one shared deadline after the handshake. Connection setup and the TLS
handshake use their existing separate socket timeouts; this is not an overall
wall-clock limit for every scan stage.

The parser accepts HTTP/1.0 and HTTP/1.1 status lines, requires a three-digit
status, validates field names and rejects embedded control bytes. It skips up
to eight interim responses, treats 101 as terminal, and only uses final response
headers. Body text cannot add a fake `Server` or `Via` observation. LF-only lines
and a status without a reason phrase are tolerated. It does not validate the
response body or all HTTP framing rules. The status-line reference is
[RFC 9112, section 4](https://www.rfc-editor.org/rfc/rfc9112.html#section-4).

`Server` is optional under
[RFC 9110, section 10.2.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.2.4).
Forwarding headers also occur on ordinary reverse proxies and CDNs. Neither
their presence nor a missing banner confirms an open proxy or VPN. A malformed
response is reported as a parsing error, not attributed to Xray.

## crt.sh and HTTP downloads

`http_get()` requires a 2xx status and no I/O error for success. Downloads use a
fixed buffer and a 512 KiB body limit; read failures and oversized bodies remain
errors. For responses without content encoding, a declared `Content-Length`
must match the bytes received. WinHTTP can otherwise report successful EOF on
a truncated response. Encoded lengths cannot be compared directly with the
body after WinHTTP decompression; transport and decompression still depend on
WinHTTP. Its timeouts apply to individual operations, not the entire download.

The crt.sh parser requires a complete JSON array of objects with positive,
integral record IDs. HTML error pages, comments, invalid records and trailing
garbage do not become positive or negative search results. Repeated IDs count
once. The older C++ field `log_entries` counts unique crt.sh records, not
independent CT logs.

`lookup_complete` means the HTTP request and response parse succeeded. A valid
empty array means this search returned no rows; it does not prove that the
certificate was never logged. crt.sh is a search service, not a verification of
all logs or SCTs. See [crt.sh](https://crt.sh/) and the
[CT log overview](https://certificate.transparency.dev/logs/).

## J3 and output fields

J3 groups matching first lines and captured byte counts, retaining the largest
group that spans an HTTP request and another probe type. It does not compare
whole bodies or authenticate a protocol. TLS record prefixes, malformed HTTP
start lines, silence and uniform responses are observations only.

JSON adds the following fields while retaining older fields:

| Location | Fields and meaning |
|---|---|
| root | `score_is_heuristic: true` |
| `tspu` | `thresholds_validated: false`, `blocking_verified: false` |
| `tls_ports[]` | `certificate_present`, `certificate_times_valid`, `cert_validity_seconds`, `certificate_expired`, `certificate_not_yet_valid` |
| `tls_ports[]` | `self_issued`, `self_signature_checked`, `self_signed`, `certificate_trust_checked: false` |
| `tls_ports[].https` | Request sent, response observed, complete/valid headers, status, first line, banner, forwarding-header observation and error |
| `tls_ports[].ct_search` | `source`, `queried`, `lookup_complete`, `found`, `result_count`, `error` |

Missing HTTPS or CT results are `null`. Legacy score labels such as `CLEAN` and
`OBVIOUSLY VPN`, and TSPU labels such as `IMMEDIATE BLOCK`, are compatibility
categories. They are not probabilities, protocol confirmation or verified
blocking results.

## Regression checks

`tests/test_web_observations.cpp` covers certificate signature and time edge
cases, HTTP parsing, CT failures and J3 grouping. `tests/test_web_socket.py`
uses only local TCP/TLS servers and temporary certificates created by
`web-probe-tests.exe`. It exercises fragmented and incomplete responses,
header/body limits, deadlines, compressed/chunked downloads, early EOF and
the actual JSON report. No external server or crt.sh request is needed.
