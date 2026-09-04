---
title: "WIMSE Workload-to-Workload Authentication with HTTP Signatures"
abbrev: "WIMSE Workload-to-Workload HTTP-Sig"
category: std

docname: draft-ietf-wimse-http-signature-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
area: "Applications and Real-Time"
workgroup: "Workload Identity in Multi System Environments"
keyword:
 - workload
 - identity
venue:
  group: "Workload Identity in Multi System Environments"
  type: "Working Group"
  mail: "wimse@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/wimse/"
  github: "ietf-wg-wimse/draft-ietf-wimse-s2s-protocol"
  latest: "https://ietf-wg-wimse.github.io/draft-ietf-wimse-s2s-protocol/draft-ietf-wimse-s2s-protocol.html"

author:
 -
    fullname: "Joe Salowey"
    organization: Palo Alto Networks
    email: joe@salowey.net
 -
    fullname: "Yaron Sheffer"
    organization: Intuit
    email: "yaronf.ietf@gmail.com"

informative:
  IANA.HTTP.MESSAGE.SIGNATURE:
    title: "HTTP Message Signature"
    target: https://www.iana.org/assignments/http-message-signature/http-message-signature.xhtml#signature-metadata-parameters

--- abstract

The WIMSE architecture defines authentication and authorization for software workloads
in a variety of runtime environments, from the most basic ones to complex
multi-service, multi-cloud, multi-tenant deployments.
This document defines one of the mechanisms to provide workload authentication,
using HTTP Signatures. While only applicable to HTTP traffic, the protocol provides end-to-end
protection of requests (and optionally, responses), even when service traffic is not end-to-end
encrypted, that is, when TLS proxies and load balancers are used.
Authentication is based on the Workload Identity Token (WIT).

--- middle

# Introduction

This document defines authentication and authorization in the context of interaction between two workloads.
This is the core component of the WIMSE architecture {{?I-D.ietf-wimse-arch}}.
This document focuses on HTTP-based services,
and the workload-to-workload call consists of a single HTTP request and its response.

One option to protect such traffic is through Mutual TLS (mTLS), and this usage is defined in {{?I-D.ietf-wimse-mutual-tls}}.
Many deployments prefer application-layer approaches, whether for lack of Certification Authority (CA) infrastructure or because
inter-service communication consists of multiple TLS hops. This document defines one such WIMSE
approach for application-layer protection.

We define a profile of the HTTP Signatures protocol {{!RFC9421}} to protect the service traffic.
Service authentication uses the Workload Identity Token (WIT) defined in {{!I-D.ietf-wimse-workload-creds}},
and the signature uses the private key associated with the WIT and thus proves possession of that key.

WIMSE is specifying two approaches for application-layer protection, both using the newly introduced
Workload Identity Token {{I-D.ietf-wimse-workload-creds}}. The first alternative {{?I-D.ietf-wimse-wpt}} is inspired by the OAuth DPoP specification {{?RFC9449}}.
The second is based on the HTTP Message Signatures RFC {{!RFC9421}}, and it is defined in this document.
{{app-layer-comparison}} includes a comparison of the two approaches.

## Deployment Architecture and Message Flow

Refer to Sec. 1.2 of {{I-D.ietf-wimse-workload-creds}} for the deployment architecture which is common to both application-level approaches, as well as the transport-level one.

# Conventions and Definitions

All terminology in this document follows {{?I-D.ietf-wimse-arch}}.

{::boilerplate bcp14-tagged}

# The Protocol: Authentication Based on HTTP Message Signatures {#http-sig-auth}

This protocol uses the Workload Identity Token {{I-D.ietf-wimse-workload-creds}} and the private key associated with its public key,
to sign the HTTP request and optionally, the response.
Formally, this is a profile of the Message Signatures specification {{!RFC9421}}.

The request is signed as per {{RFC9421}}. The following derived components MUST be signed:

* `@method`
* `@path`
* `@query`

This profile uses `@path` and `@query` rather than `@request-target`, which is NOT RECOMMENDED outside HTTP/1.1 ({{Section 2.2.5 of RFC9421}}). `@query` is included even when the request has no query component; in that case its value is `?` ({{Section 2.2.7 of RFC9421}}).
The `@authority` derived component is not included: TLS-terminating proxies and load balancers commonly rewrite the authority (see {{I-D.ietf-wimse-arch}} and {{middleboxes}}), so signing it would break those deployments. Recipient binding is carried instead by the mandatory `wimse-aud` signature parameter ({{wimse-aud-param}}).

In addition, the following request headers MUST be signed when they exist:

* `Content-Type`
* `Content-Digest`
* `Authorization`
* `Txn-Token` {{?I-D.ietf-oauth-transaction-tokens}}
* `Workload-Identity-Token`

If the response is signed, the following components MUST be signed:

* `@status`
* `@method;req`
* `@path;req`
* `@query;req`
* `Content-Type` if it exists
* `Content-Digest` if it exists
* `Workload-Identity-Token`

To ensure the message is fully integrity-protected, if the request or response includes a message body, the sender MUST include
(and the receiver MUST verify) a Content-Digest header. This implies the receiver MUST compute the Content-Digest value for the message content received and compare it with the Content-Digest value provided in the message.

For both requests and responses, the following signature parameters MUST be included:

* `created`
* `expires` - expiration MUST be short, e.g. on the order of minutes. The WIMSE architecture will provide separate
mechanisms in support of long-lived compute processes.
* `nonce`
* `tag` - the value for implementations of this specification is `wimse-workload-to-workload`

For requests only, the following signature parameter MUST also be included:

* `wimse-aud` ({{wimse-aud-param}})

For requests only, the following signature parameter MAY also be included:

* `wimse-sign-response` ({{wimse-sign-response-param}})

For responses only, the following signature parameter MUST also be included:

* `wimse-req-nonce` ({{wimse-req-nonce-param}})

The following signature parameters in the `Signature-Input` header MUST NOT be used:

* `keyid` - The signing key is sent along with the message in the WIT. Additionally specifying the key identity would add confusion.
* `alg` - The signature algorithm is specified in the `jwk` section of the `cnf` claim in the WIT. See {{I-D.ietf-wimse-workload-creds}} and Sec. 3.3.7 of {{RFC9421}} for details.

It is RECOMMENDED to include only one signature with the HTTP message.
The WIMSE signature is the one whose `tag` parameter is `wimse-workload-to-workload` ({{Section 7.2.7 of RFC9421}}). If no signature has that `tag` value, the message does not carry a WIMSE HTTP signature. If more than one signature has that `tag` value, the recipient MUST reject the message. When more than one signature is present, recipients MUST use that `tag` to find the WIMSE signature; they MUST NOT choose by label ({{Section 7.2.5 of RFC9421}}).

Senders MUST generate each `nonce` at random with sufficient length that the probability of collision is negligible among all nonces a recipient might observe within the lifetime of a signature. Members of a sender cluster therefore need not coordinate nonce generation.

Recipients MAY maintain a replay cache and SHOULD reject a message (request or response) whose `nonce` they have already seen. What nonces are remembered, and for how long, is a local policy matter; this document does not require replay caches to be shared across validators. Without such sharing, replay to a different cluster member can still succeed.

For clarity: the signature's lifetime (the `expires` signature parameter) is different and typically much shorter than the WIT's lifetime, denoted by its `exp` claim.

Implementers need to be aware that the WIT is extracted from the message before the message signature is validated. Recipients of signed HTTP messages MUST validate the WIT as specified in {{Section 5.1.4 of I-D.ietf-wimse-workload-creds}} before validating the HTTP message signature. They MUST ensure that the message is not processed further before it has been fully validated.

## The `wimse-aud` Signature Parameter {#wimse-aud-param}

{{RFC9421}} defines signature parameters for HTTP message signatures: metadata carried in the `Signature-Input` field
alongside the covered components. That metadata is covered by the signature as the `@signature-params` component value
(Section 2.3 of {{RFC9421}}), which is always the last line of the signature base.

This document defines the `wimse-aud` signature metadata parameter for requests.
It is a String parameter.
Using a signature parameter carries the audience explicitly in `Signature-Input`, so the value is protected by the signature and is not affected by hop-by-hop rewriting of the request URI.

The sender MUST set `wimse-aud` to an audience value that identifies the intended recipient of the request.
By default, the sender uses the HTTP target URI ({{Section 7.1 of !RFC9110}}) of the request, without query or fragment components, as known to the sender.
When intermediaries rewrite the request URI, or when that string would not match what the recipient expects, the sender uses a deployment-specific audience value that the recipient can recognize.
The audience identifies the intended recipient of the proof; it is distinct from the sender's Workload Identifier in the WIT `sub` claim.
The recipient MUST be able to verify that the audience refers to it, using trusted configuration rather than untrusted request fields such as `Host`.
See "Workload Identifiers and Authentication Granularity" in {{I-D.ietf-wimse-workload-creds}}.

## The `wimse-sign-response` Signature Parameter {#wimse-sign-response-param}

This document defines the `wimse-sign-response` signature metadata parameter for requests.
It is a Boolean parameter ({{Section 3.3.6 of ?RFC8941}}).
When present with the value true, the client requires the server to sign the HTTP response
to this request as specified in {{signing-the-response}}.

If the client is configured to require a signed response, it MUST include `wimse-sign-response` with the Boolean value true in the request's `Signature-Input`.

This parameter is not mandatory. Moreover, the server MAY sign the response even if this parameter is missing from the request.

## The `wimse-req-nonce` Signature Parameter {#wimse-req-nonce-param}

This document defines the `wimse-req-nonce` signature metadata parameter for signed responses.
This parameter binds requests to responses and prevents a malicious
server-side component or middlebox from replaying responses to the wrong client.

Every signed response MUST include `wimse-req-nonce`. The server MUST set it to the value of the `nonce` signature parameter from the `Signature-Input` of the request that triggered the response.

## Signing the Response {#signing-the-response}

Protecting the response by signing it with the server's WIT is RECOMMENDED but not required. In particular, if the response
may be exceptionally large or is expected to be streamed, signing it may not be practical.

Response signing is required of the server for a given exchange when either of the following is true:

* The request's `Signature-Input` includes `wimse-sign-response` with the Boolean value true ({{wimse-sign-response-param}}).
* Local policy at the server requires response signing for that exchange.

If the server is required to sign the response but cannot produce a signed response (for example, because the response is streamed or
exceptionally large), it MUST NOT return a successful unsigned response; it MUST return an error
as described in {{error-conditions}}.

The client MUST reject an unsigned response when the request's `Signature-Input` included `wimse-sign-response` with the Boolean value true.

If the client did not require a signed response via `wimse-sign-response`, server-side local-policy signing is opportunistic from the client's point of view: the client has no signal that a signature was expected, so a middlebox that strips a signed response leaves an ordinary unsigned response that the client MUST accept. The server MAY still sign in that case. Whenever a signed response is present, the client MUST validate it and reject it if validation fails.

When validating a signed response, the client MUST verify that `wimse-req-nonce` is present and equals the `nonce` from the corresponding request.

As described in {{Section 5 of RFC9421}}, either client or server MAY send an
`Accept-Signature` header,
but is not required to do so. The `Accept-Signature` header indicates a
preference for signed messages but does not mandate that responses be signed.
When a client sends `Accept-Signature` in a request, it MUST list the
response components it wishes to have signed (including at least those specified above for signed
responses). When a server sends `Accept-Signature` in a response, it MUST
list the request components it wishes to have signed in subsequent requests (minimally those
specified above for signed requests).

## Error Conditions {#error-conditions}

Errors may occur during the processing of the message signature. If the signature verification fails for any reason,
such as an invalid signature, an expired validity time window, or a malformed data structure, an error is returned. Typically,
this will be in response to an API call. An HTTP status code such as 400 (Bad Request) is appropriate. The response could
include more details as per {{?RFC9457}}, such as an indicator that the wrong key material or algorithm was used.  The use of HTTP
status code 401 is NOT RECOMMENDED for this purpose because it requires a WWW-Authenticate with acceptable HTTP auth mechanisms in
the error response and an associated Authorization header in the subsequent request. The use of these headers for the WIT is not compatible
with this specification.

If the client required a signed response via `wimse-sign-response` and the server cannot sign the response,
the server SHOULD return 400 (Bad Request) or 501 (Not Implemented), optionally with a
{{?RFC9457}} problem details body indicating that a signed response cannot be provided.


## Example Requests and Responses

Following is a non-normative example of a signed request and a signed response.

The caller uses this keypair:

~~~ jwk
{::include includes/sigs-svca-jwk.txt}
~~~
{: title="Caller Private Key"}

The caller uses its keypair and generates the following HTTP request:

~~~ http
{::include includes/sigs-request.txt.out}
~~~
{: title="Signed Request"}

Assuming that the workload being called has the following keypair:

~~~ jwk
{::include includes/sigs-svcb-jwk.txt}
~~~
{: title="Callee Private Key"}

A signed response would be:

~~~ http
{::include includes/sigs-response.txt.out}
~~~
{: title="Signed Response"}

# Implementation Status

<cref>Note to RFC Editor: please remove this section, as well as the reference to RFC 7942, before publication.</cref>

This section records the status of known implementations of the protocol defined by this specification at the time of posting of this Internet-Draft, and is based on a proposal described in {{!RFC7942}}. The description of implementations in this section is intended to assist the IETF in its decision processes in progressing drafts to RFCs.  Please note that the listing of any individual implementation here does not imply endorsement by the IETF.  Furthermore, no effort has been spent to verify the information presented here that was supplied by IETF contributors. This is not intended as, and must not be construed to be, a catalog of available implementations or their features.  Readers are advised to note that other implementations may exist.

According to RFC 7942, "this will allow reviewers and working groups to assign due consideration to documents that have the benefit of running code, which may serve as evidence of valuable experimentation and feedback that have made the implemented protocols more mature.  It is up to the individual working groups to use this information as they see fit".

## Cofide

* Organization: Cofide
* Implementation: <https://github.com/cofide/wimse-s2s-httpsig-poc>
* Maturity:
    * WIT + HTTP Message Signatures: proof-of-concept
* Coverage: WIT, HTTP Message Signatures
* License: Apache 2.0
* Contact: jason@cofide.io
* Last updated: 13-Nov-2025

## wimsey

* Organization: independent
* Implementation: <https://github.com/kanywst/wimsey>
* Maturity:
    * WIT + HTTP Message Signatures: alpha
* Coverage: WIT, HTTP Message Signatures, signed responses
* License: Apache 2.0
* Contact: [kanywst on GitHub](https://github.com/kanywst)
* Last updated: 27-Aug-2026

# Security Considerations

This section includes security considerations that are specific to the HTTP Signature protocol defined here. Refer to
{{I-D.ietf-wimse-workload-creds}} for more generic security considerations associated with the workload identity
and its WIT representation.

## Workload Identity Token and Proof of Possession

The Workload Identity Token (WIT) is bound to a secret cryptographic key and is
always presented with a proof of possession (PoP) as described in
{{I-D.ietf-wimse-workload-creds}}. The WIT is a general purpose token that can be presented
in multiple contexts. The WIT and its PoP are only used in the
application-layer options, and neither is used in mTLS. The WIT MUST NOT be
used as a bearer token. While this helps reduce the sensitivity of the token it
is still possible that a token and its PoP may be captured and
replayed within the PoP's lifetime.

The HTTP Signature profile presented here binds the PoP to the critical parts of the HTTP request (and potentially
response), including the request method, path, query, the intended audience (`wimse-aud`), and the message content.
The audience is a signed signature parameter rather than a re-derived URI component, so it survives intermediaries that rewrite the authority.
This profile does not cover `@authority` for that reason ({{http-sig-auth}}).
This eliminates most of the risk associated with active attackers on a middlebox.

In addition, the following mitigations should be used:

* Preventing Eavesdropping and Interception with TLS

An attacker observing or intercepting the communication channel can view the token and its PoP and attempt to replay it to gain an advantage. In order to prevent this, the
token and PoP MUST be sent over a secure, server authenticated TLS connection unless a secure channel is provided by some other mechanisms. Hostname validation according
to Section 6.3 of {{!RFC9525}} MUST be performed by the client.

* Limiting Signature Lifespan

The signature lifespan MUST be limited by using a tight `expires` value, taking into account potential clock skew and
processing latency, but usually within minutes of the message sending time. Signatures received outside their validity time MUST be rejected.

* Replay Protection

A signed message includes the `nonce` signature parameter. This parameter SHOULD be used by the receiver to perform basic replay protection: a nonce that has already been seen SHOULD cause the message to be rejected.
Depending upon the design of the system it may be difficult to synchronize the replay cache across all message validators.
If an attacker can somehow influence the identity of the validator (e.g. which cluster member receives the message) then
replay protection would not be effective.

## Middle Boxes {#middleboxes}

In some deployments the Workload Identity Token and PoP
(signature) may pass through multiple systems. The communication between the
systems is over TLS, but the WIT and signature are available in the clear at each
intermediary.  While the intermediary cannot modify the token or the
information within the signature they can attempt to capture and replay the message or modify
unsigned information, such as any HTTP headers that remain unsigned.

Mitigations listed in the protocol provide a reasonable level of security in these situations, in particular
if responses are signed in addition to requests.

## Privacy Considerations

WITs and the signatures may contain private information such as user names or other identities. Care must be taken to prevent disclosure of this information. The use of TLS helps protect the privacy of WITs and PoPs.

WITs are typically associated with a workload and not a specific user, however
in some deployments the workload may be associated directly to a user. In those cases a deployment should evaluate if the disclosure of
WITs or signatures can be used to track a user.

# Security Goals

This section defines semiformal security goals for this protocol, when used in conjunction with the WIT credential. Our aim
is to inform developers and for these goals to eventually evolve into formal verification of the protocol.

## Prerequisites

The following are out of scope of the protocol and their security is assumed.

* There exists a WIT Issuer which is trusted to issue credentials honestly.
* Workloads have a way to authenticate themselves to the Issuer and be provisioned with a valid WIT, associated
with their WIMSE identity.
* All workloads are provisioned with trust anchors that allow them to validate incoming WITs.
* The entire authorization subsystem is out of scope and trusted. This can potentially include
provisioning and enforcement of an authorization policy, issuance of transaction tokens
and workload attestation.
* All workload-to-workload traffic is TLS-protected. However TLS may be terminated on one or more middleboxes
and the TLS endpoint identity (or identities) is not associated with a WIMSE identity.
* As a result, all workload-to-workload traffic is confidential and (assuming honest participants) is only available to sender,
receiver, and any TLS-terminating middleboxes that process the traffic.

## Authentication

* A workload receiving a request can validate that it is signed correctly, and can identify the sender.
* A workload receiving a response can similarly validate the signature and identify the sender when a signed response is present.
* The above implies that a stolen WIT cannot be used by an entity other than its owner.

## Integrity

* No requests can be modified without detection by the recipient. Integrity of
  all present HTTP headers specified in this document is protected, as well as
the derived components listed in {{http-sig-auth}}, the signature parameters
(including `wimse-aud` and `wimse-sign-response` on requests and `wimse-req-nonce` on responses)
as covered by `@signature-params` in {{RFC9421}}, and
the message content (when present).
* No responses can be modified without detection when response signing is required
({{signing-the-response}}) and the recipient validates incoming responses.
* Note: Headers not specified in this document may remain unsigned and could
  potentially be modified or deleted by intermediaries without detection.

## Replay and Deletion

* Replay protection is not strictly mandated because of implementation
  considerations (e.g., distributed system challenges with synchronizing replay
caches across validators). Therefore it is not claimed as
a goal, though implementations SHOULD attempt to detect replays where feasible.
We note that since most of the message is signed, replay attacks are only possible in a
context where the request would be accepted as valid, and this mitigates the risk to some extent.
* When a signed response is present, validating `wimse-req-nonce` mitigates replay of that response to a client other than the one that sent the triggering request.
* Undetected deletion of a request/response pair is prevented only when the client required a signed response via `wimse-sign-response` with the Boolean value true and rejects an unsigned response. Server local-policy signing alone does not provide that guarantee ({{signing-the-response}}).


# IANA Considerations {#iana-considerations}

## HTTP Signature Metadata Parameters Registration

IANA is requested to register the following entries in the "HTTP Signature Metadata Parameters" registry {{IANA.HTTP.MESSAGE.SIGNATURE}}, per the registration template in Section 6.3.1 of {{RFC9421}}:

* `wimse-aud`, per {{iana-wimse-aud-param}}.
* `wimse-sign-response`, per {{iana-wimse-sign-response-param}}.
* `wimse-req-nonce`, per {{iana-wimse-req-nonce-param}}.

### `wimse-aud` {#iana-wimse-aud-param}

* Name: `wimse-aud`
* Description: the WIMSE message audience. Request signatures only; binds the HTTP message signature to the intended recipient.
* Reference: RFC XXX, {{wimse-aud-param}}.

### `wimse-sign-response` {#iana-wimse-sign-response-param}

* Name: `wimse-sign-response`
* Description: Boolean; when true on a request signature, the client requires the server to sign the corresponding HTTP response.
* Reference: RFC XXX, {{wimse-sign-response-param}}.

### `wimse-req-nonce` {#iana-wimse-req-nonce-param}

* Name: `wimse-req-nonce`
* Description: on response signatures, the `nonce` value from the triggering request's `Signature-Input`; binds the response to that request.
* Reference: RFC XXX, {{wimse-req-nonce-param}}.

--- back

# Document History
<cref>RFC Editor: please remove before publication.</cref>

## draft-ietf-wimse-http-signature-07

* WGLC: replace `@request-target` with `@path` and `@query` (#297).
* WGLC: require `wimse-req-nonce` on every signed response, not only when the client required one (#297).
* WGLC: recipients reject duplicate nonces without regard to sender (#297).
* WGLC: require `wimse-sign-response` when the client is configured to require a signed response (#301).
* WGLC: select the WIMSE signature by `tag`, not by label (#301).
* WGLC: clarify that deletion detection and mandatory-response guarantees require `wimse-sign-response`; local-policy signing is opportunistic for the client (#305).
* WGLC: clarify `wimse-aud` (always present; sender default is target URI; deployment-specific when needed); omit `@authority`; state audience binding in the WIT and PoP security considerations (#305, #297).
* Regenerate non-normative examples for `@path`/`@query`, `wimse-sign-response`, and `wimse-req-nonce`.
* Editorial: consistent use of "proof of possession"/"PoP", with the abbreviation expanded on first use.
* Reference the WIT validation procedure in {{I-D.ietf-wimse-workload-creds}} (#290).

## draft-ietf-wimse-http-signature-06

* Add `wimse-sign-response` request signature parameter so clients can mandate a signed response; regenerate examples (#277).

## draft-ietf-wimse-http-signature-05

* Regenerate non-normative request/response examples so the signed response includes `wimse-req-nonce` matching the request `nonce` (#274).

## draft-ietf-wimse-http-signature-04

* On signed responses, require `wimse-req-nonce` (request binding); register with IANA. Non-normative response example not updated accordingly; the `Signature` value was not regenerated (see issue tracker).

## draft-ietf-wimse-http-signature-03

* Replace `Wimse-Audience` HTTP header with the `wimse-aud` signature metadata parameter ({{RFC9421}}); register with IANA (HTTP Signature Metadata Parameters). Non-normative request example updated accordingly; the `Signature` value was not regenerated (see issue tracker).

## draft-ietf-wimse-http-signature-02

* Add new `Wimse-Audience` HTTP header (superseded by `wimse-aud` in -03).

## draft-ietf-wimse-http-signature-01

* Clarified response signing.
* Clarified signature vs. token lifetime.
* Added security goals.
* Added an Implementation Status section.

## draft-ietf-wimse-http-signature-00

* Initial version, extracted from the -07 draft with minimal edits.

## draft-ietf-wimse-s2s-protocol-07

* Rework the WPT's `oth` claim.
* Update the media types.
* Discuss extensibility of WIT and WPT.
* Clarify error handling, specifically why not HTTP 401.
* Correct the code examples.
* Add registration request content for a `wimse` URI scheme.
* New section on key management.
* Use of the `Accept-Signature` header.

## draft-ietf-wimse-s2s-protocol-06

* Explicit definition of the Workload Identity Certificate.
* Definition of the validation of workload identifiers as part of workload authentication. Still work in progress.

## draft-ietf-wimse-s2s-protocol-05

* Removed the entire Workload Identity section which is now covered in the Architecture document.
* Content-Digest is mandatory with HTTP-Sig.
* Some wording on extending the protocol beyond HTTP.
* IANA considerations.

## draft-ietf-wimse-s2s-protocol-04

* Require `cnf.jwk.alg` in WIT which restricts signature algorithm of WPT or HTTP-Sig.
* Replay protection as a SHOULD for both WPT and HTTP-Sig.
* Consolidate terminology with the Architecture draft.

## draft-ietf-wimse-s2s-protocol-03

* Consistently use "workload".
* Implement comments from the SPIFFE community.
* Make `iss` claim in WIT optional and add wording about its relation to key distribution.
* Remove `iss` claim from WPT.
* Make `jti` claim in WIT optional.
* Error handling for the application-level methods.

## draft-ietf-wimse-s2s-protocol-02

* Coexistence with bearer tokens.
* Improve the architecture diagram.
* Some more ABNF.
* Clarified identifiers and URIs.
* Moved an author to acknowledgments.

## draft-ietf-wimse-s2s-protocol-01

* Addressed multiple comments from Pieter.
* Clarified WIMSE identity concepts, specifically "trust domain"
and "workload identifier".
* Much more detail around mTLS, including some normative language.
* WIT (the identity token) is now included in the WPT proof of possession.
* Added a section comparing the DPoP-inspired app-level security option to
the Message Signature-based alternative.

## draft-ietf-wimse-s2s-protocol-00

* Initial WG draft, an exact copy of draft-sheffer-wimse-s2s-protocol-00
* Added this document history section

# Comparing the DPoP Inspired Option with Message Signatures {#app-layer-comparison}

The two workload protection options have different strengths and weaknesses regarding implementation
complexity, extensibility, and security.
Here is a summary of the main differences between
{{I-D.ietf-wimse-wpt}} and {{http-sig-auth}}.

- The DPoP-inspired solution is less HTTP-specific, making it easier to adapt for
other protocols beyond HTTP. This flexibility is particularly valuable for
asynchronous communication scenarios, such as event-driven systems.

- Message Signatures, on the other hand, benefit from an existing HTTP-specific RFC with
some established implementations. This existing groundwork means that this option could
be simpler to deploy, to the extent such implementations are available and easily integrated.

- Given that the WIT (Workload Identity Token) is a type of JWT, the
DPoP-inspired approach that also uses JWT is less complex and technology-intensive than Message
Signatures. In contrast, Message Signatures introduce an additional layer of
technology, potentially increasing the complexity of the overall system.

- Message Signatures offer superior integrity protection, particularly by mitigating
message modification by middleboxes. See also {{middleboxes}}.

- A key advantage of Message Signatures is that they support response signing.
This opens up the possibility for future decisions about whether to make
response signing mandatory, allowing for flexibility in the specification
and/or in specific deployment scenarios.

- In general, Message Signatures provide greater flexibility compared to
the DPoP-inspired approach. Future versions of this specification (and subsequent implementations) can decide
whether specific aspects of message signing, such as coverage of particular fields,
should be mandatory or optional. Covering more fields will constrain the proof
so it cannot be easily reused in another context, which is often a security improvement. The DPoP inspired approach could
be designed to include extensibility to sign other fields, but this would make it closer to
trying to reinvent Message Signatures.

# Acknowledgments
{:numbered="false"}

The authors would like to thank Pieter Kasselman for his detailed comments,
Kieran Sweeney and Anton Sokolov for their WGLC reviews,
as well as Jason Costello, Maartje Eyskens, Radosław Piliszek and kanywst for implementing this draft and sharing their learnings.

We thank Daniel Feldman for his contributions to earlier versions of this document. We also thank Arndt Schwenkschuster and Brian Campbell who coauthored
the grand unified WIMSE Workload to Workload protocol draft.
