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
    organization: CyberArk
    email: joe@salowey.net
 -
    fullname: "Yaron Sheffer"
    organization: Intuit
    email: "yaronf.ietf@gmail.com"

normative:

informative:

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

One option to protect such traffic is through Mutual TLS, and this usage is defined in {{?I-D.ietf-wimse-mutual-tls}}.
Many deployments prefer application-level approaches, whether for lack of CA infrastructure or because
inter-service communication consists of multiple separate TLS hops. This document defines one of the two WIMSE
approaches for application-level protection.

We define a profile of the HTTP Signatures protocol {{!RFC9421}} to protect the service traffic.
Service authentication uses the Workload Identity Token (WIT) defined in {{!I-D.ietf-wimse-workload-creds}},
and the signature uses the private key associated with the WIT and thus proves possession of that key.

As noted, the WIMSE working group is specifying two alternatives for application-level protection, both using the newly introduced
Workload Identity Token {{I-D.ietf-wimse-workload-creds}}. The first alternative {{?I-D.ietf-wimse-wpt}} is inspired by the OAuth DPoP specification.
The second is based on the HTTP Message Signatures RFC, and this is the one defined in this document.
{{app-level-comparison}} includes a comparison of the two alternatives.

## Deployment Architecture and Message Flow

Refer to Sec. 1.2 of {{I-D.ietf-wimse-workload-creds}} for the deployment architecture which is common to all three
protection options, including the one described here.

# Conventions and Definitions

All terminology in this document follows {{?I-D.ietf-wimse-arch}}.

{::boilerplate bcp14-tagged}

# The Protocol: Authentication Based on HTTP Message Signatures {#http-sig-auth}

This protocol uses the Workload Identity Token {{I-D.ietf-wimse-workload-creds}} and the private key associated with its public key,
to sign the request and optionally, the response.
Formally, this is a profile of the Message Signatures specification {{!RFC9421}}.

The request is signed as per {{RFC9421}}. The following derived components MUST be signed:

* `@method`
* `@request-target`

In addition, the following request headers MUST be signed when they exist:

* `Content-Type`
* `Content-Digest`
* `Authorization`
* `Txn-Token` {{?I-D.ietf-oauth-transaction-tokens}}
* `Workload-Identity-Token`

If the response is signed, the following components MUST be signed:

* `@status`
* `@method;req`
* `@request-target;req`
* `Content-Type` if it exists
* `Content-Digest` if it exists
* `Workload-Identity-Token`

To ensure the message is fully integrity-protected, if the request or response includes a message body, the sender MUST include
(and the receiver MUST verify) a Content-Digest header.

For both requests and responses, the following signature parameters MUST be included:

* `created`
* `expires` - expiration MUST be short, e.g. on the order of minutes. The WIMSE architecture will provide separate
mechanisms in support of long-lived compute processes.
* `nonce`
* `tag` - the value for implementations of this specification is `wimse-workload-to-workload`

The following signature parameters in the `Signature-Input` header MUST NOT be used:

* `keyid` - The signing key is sent along with the message in the WIT. Additionally specifying the key identity would add confusion.
* `alg` - The signature algorithm is specified in the `jwk` section of the `cnf` claim in the WIT. See {{I-D.ietf-wimse-workload-creds}} and Sec. 3.3.7 of {{RFC9421}} for details.

It is RECOMMENDED to include only one signature with the HTTP message.
If multiple ones are included, then the signature label included in both the `Signature-Input` and `Signature` headers SHOULD
be `wimse`.

A sender MUST ensure that each nonce it generates is unique, at least among messages sent to the same recipient.
To detect message replays,
a recipient SHOULD reject a message (request or response) if a nonce generated by a certain peer is seen more than once.

For clarity: the signature's lifetime (the `expires` signature parameter) is different and typically much shorter than the WIT's lifetime, denoted by its `exp` claim.

Implementors need to be aware that the WIT is extracted from the message before the message signature is validated. Recipients of signed HTTP messages MUST validate the signature and content of the WIT before validating the HTTP message signature. They MUST ensure that the message is not processed further before it has been fully validated.

Either client or server MAY send an `Accept-Signature` header, but is not required to do so. When this header is sent, it MUST include the header components listed above.

## Error Conditions

Errors may occur during the processing of the message signature. If the signature verification fails for any reason,
such as an invalid signature, an expired validity time window, or a malformed data structure, an error is returned. Typically,
this will be in response to an API call. An HTTP status code such as 400 (Bad Request) is appropriate. The response could
include more details as per {{?RFC9457}}, such as an indicator that the wrong key material or algorithm was used.  The use of HTTP
status code 401 is NOT RECOMMENDED for this purpose because it requires a WWW-Authenticate with acceptable http auth mechanisms in
the error response and an associated Authorization header in the subsequent request. The use of these headers for the WIT is not compatible
with this specification.


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

# Security Considerations

This section includes security considerations that are specific to the HTTP Signature protocol defined here. Refer to
<cref>Security Considerations section of</cref> {{I-D.ietf-wimse-workload-creds}} for more generic security considerations associated with the workload identity
and its WIT representation.

## Workload Identity Token and Proof of Possession

The Workload Identity Token (WIT) is bound to a secret cryptographic key and is
always presented with a proof of possession as described in
{{I-D.ietf-wimse-workload-creds}}. The WIT is a general purpose token that can be presented
in multiple contexts. The WIT and its PoP are only used in the
application-level options, and both are not used in MTLS. The WIT MUST NOT be
used as a bearer token. While this helps reduce the sensitivity of the token it
is still possible that a token and its proof of possession may be captured and
replayed within the PoP's lifetime.

The HTTP Signature profile presented here binds the proof of possession to the critical parts of the HTTP request (and potentially
response), including the Request URI and the message body. This
eliminates most of the risk associated with active attackers on a middlebox.

In addition, the following mitigations should be used:

* Preventing Eavesdropping and Interception with TLS

An attacker observing or intercepting the communication channel can view the token and its proof of possession and attempt to replay it to gain an advantage. In order to prevent this the
token and proof of possession MUST be sent over a secure, server authenticated TLS connection unless a secure channel is provided by some other mechanisms. Hostname validation according
to Section 6.3 of {{!RFC9525}} MUST be performed by the client.

* Limiting Signature Lifespan

The signature lifespan MUST be limited by using a tight `expires` value, taking into account potential clock skew and
processing latency, but usually within minutes of the message sending time. Signatures received outside their validity time MUST be rejected.

* Replay Protection

A signed message includes the `jti` claim that MUST uniquely identify it, within the scope of a particular sender.
This claim SHOULD be used by the receiver to perform basic replay protection against messages it has already seen.
Depending upon the design of the system it may be difficult to synchronize the replay cache across all messages validators.
If an attacker can somehow influence the identity of the validator (e.g. which cluster member receives the message) then
replay protection would not be effective.

## Middle Boxes {#middleboxes}

In some deployments the Workload Identity Token and proof of possession
(signature) may pass through multiple systems. The communication between the
systems is over TLS, but the WIT and signature are available in the clear at each
intermediary.  While the intermediary cannot modify the token or the
information within the signature they can attempt to capture and replay the the message or modify
unsigned information, such as proprietary HTTP headers that may remain unsigned.

Mitigations listed in the protocol provide a reasonable level of security in these situations, in particular
if responses are signed in addition to requests.

## Privacy Considerations

WITs and the signatures may contain private information such as user names or other identities. Care must be taken to prevent disclosure of this information. The use of TLS helps protect the privacy of WITs and proofs of possession.

WITs are typically associated with a workload and not a specific user, however
in some deployments the workload may be associated directly to a user. While
these are exceptional cases a deployment should evaluate if the disclosure of
WITs or signatures can be used to track a user.


# IANA Considerations

This document does not include any IANA considerations.

--- back

# Document History
<cref>RFC Editor: please remove before publication.</cref>

## draft-ietf-wimse-http-signature-00

* Initial version, extracted from the -07 draft with minimal edits.

## draft-ietf-wimse-s2s-protocol-07

* Rework the WPT's `oth` claim.
* update the media types.
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
* Error handling for the application level methods.

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

# Comparing the DPoP Inspired Option with Message Signatures {#app-level-comparison}

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
the DPoP-inspired approach. Future versions of this draft (and subsequent implementations) can decide
whether specific aspects of message signing, such as coverage of particular fields,
should be mandatory or optional. Covering more fields will constrain the proof
so it cannot be easily reused in another context, which is often a security improvement. The DPoP inspired approach could
be designed to include extensibility to sign other fields, but this would make it closer to
trying to reinvent Message Signatures.

# Acknowledgments
{:numbered="false"}

The authors would like to thank Pieter Kasselman for his detailed comments.

We thank Daniel Feldman for his contributions to earlier versions of this document.
