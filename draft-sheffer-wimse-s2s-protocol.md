---
title: "WIMSE Service to Service Authentication"
abbrev: "WIMSE S2S Auth"
category: std

docname: draft-sheffer-wimse-s2s-protocol-latest
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
  github: "yaronf/wimse-s2s"
  latest: "https://yaronf.github.io/wimse-s2s/draft-sheffer-wimse-s2s-protocol.html"

author:
 -
    fullname: "Brian Campbell"
    organization: "Ping Identity"
    email: bcampbell@pingidentity.com
 -
    fullname: "Daniel Feldman"
 -
    fullname: "Joe Salowey"
    organization: Venafi
    email: joe.salowey@gmail.com
 -
    fullname: "Arndt Schwenkschuster"
    organization: Microsoft
    email: arndts.ietf@gmail.com
 -
    fullname: "Yaron Sheffer"
    organization: Intuit
    email: "yaronf.ietf@gmail.com"

normative:

informative:


--- abstract

TODO Abstract


--- middle

# Introduction

This document defines authentication and authorization in the context of interaction between two workloads.
This is the core component of the WIMSE architecture {{?I-D.ietf-wimse-arch}}.
Assume that Service A needs to call Service B. For simplicity, this document focuses on HTTP-based services,
and the service-to-service call consists of a single HTTP request and its response.
We define the credentials that both services should possess and how they are used to protect the HTTP exchange.

There are multiple deployment styles in use today, and they result in different security properties.
We propose to address them differently.

* Many use cases have various middleboxes inserted between pairs of services, resulting in a transport layer
that is not end-to-end encrypted. We propose to address these use cases by protecting the HTTP messages at the application
level ({{app-level}}).

* The other commonly deployed architecture has a mutual-TLS connection between each pair of services. This setup
can be addressed by a simpler solution ({{mutual-tls}}).

It is an explicit goal of this protocol that a service deployment can include both architectures across a multi-chain call.
In other words, Service A can call Service B with mutual TLS protection,
while the next call to Service C is protected at the application level.

For application-level protection we currently propose two alternative solutions, one inspired by DPoP {{?RFC9449}} and
one which is a profile of HTTP Message Signatures {{!RFC9421}}. The design team believes that we need to pick
one of these two alternatives for standardization, once we have understood their pros and cons.

## Deployment Architecture and Message Flow

Regardless of the transport between the workloads, we assume the following logical architecture:

~~~ aasvg
+------------+               +------------+
|            |               |            |
|            |               | Workload B |
| Workload A |==============>|            |
|            |               |   +--------+
|            |               |   |  PEP   |
+------------+               +---+--------+
      ^                        ^     ^
      |                        |     |
      | +----------------------+     |
      | |                            |
      v v                            v
+------------+               +------------+
|            |               |            |
|  Identity  |               |    PDP     |
|   Server   |               | (optional) |
|            |               |            |
+------------+               +------------+
~~~

The Identity Server provisions credentials to each of the workloads. At least Workload A (and possibly both) must be provisioned
with a credential before the call can proceed. Details of communication with the Identity Server are out of scope
of this document, however we do describe the credential received by the workload.

PEP is a Policy Enforcement Point, the component that allows the call to go through or blocks it. PDP is an optional
Policy Decision Point, which may be deployed in architectures where policy management is centralized. All details of
policy management and message authorization are out of scope of this document.

The high-level message flow is as follows:

* Workload A obtains a credential from the Identity Server. This happens periodically, e.g. once every 24 hours.
* Workload A makes an HTTP call into Workload B. This is a regular HTTP request, with the additional protection
mechanisms defined below.
* Workload B now authenticates Workload A and decides whether to authorize the call.
In certain architectures, Workload B may need to consult with an external server to decide whether to accept the call.
* Workload B returns a response to Workload A, which may be an error response or a regular one.

# Conventions and Definitions

This document uses "service" and "workload" interchangeably. Otherwise, all terms are as defined by {{?I-D.ietf-wimse-arch}}.

{::boilerplate bcp14-tagged}

# Application Level Service To Service Authentication {#app-level}

## The WIMSE ID Token

## Option 1: DPoP-Inspired Authentication

## Option 2: Authentication Based on HTTP Message Signatures

This option uses the WIMSE Identity Token (ref TBD) to sign the request and optionally, the response.
This specification defines a profile of the Message Signatures specification {{!RFC9421}}.

The request is signed as per {{RFC9421}}. The following derived components MUST be signed:

* `@method`
* `@request-target`

In addition, the following headers MUST be signed when they exist:

* `Content-Type`
* `Content-Digest`
* `Authorization`
* `Txn-Token` {{?I-D.ietf-oauth-transaction-tokens}}
* TBD that includes the WIT

If the response is signed, the following components MUST be signed:

* `@status`
* `@method;req`
* `@request-target;req`
* `Content-Type` if it exists
* `Content-Digest` if it exists
* TBD that includes the WIT

For both requests and responses, the following signature parameters MUST be included:

* `created`
* `expires` - expiration MUST be short, e.g. on the order of minutes. The WIMSE architecture will provide seperate
mechanisms in support of long-lived compute processes.
* `nonce`
* `tag` - the value for implementations of this specification is `wimse-service-to-service`

Since the signing key is sent along with the message, the `keyid` parameter SHOULD NOT be used.

It is RECOMMENDED to include only one signature with the HTTP message.
If multiple ones are included, then the signature label included in both the `Signature-Input` and `Signature` headers SHOULD
be `wimse`.

A sender MUST ensure that each nonce it generates is unique, at least among messages sent to the same recipient.
To detect message replays,
a recipient MAY reject a message (request or response) if a nonce is repeated.

To promote interoperability, the `ecdsa-p256-sha256` signing algorithm MUST be implemented
by general purpose implementations of this spec.

OPEN ISSUE: do we use the `Accept-Signature` field to signal that the response must be signed?

Following is a non-normative example of a signed request and a signed response, using the keys mentioned in Section TBD.

~~~ http
GET /gimme-ice-cream?flavor=vanilla HTTP/1.1
Host: example.com
Authorization: Basic c3BpZmZlOi8vcmVhbG0uZXhhbXBsZS5jb20vc3ZjMTphYmMxMjM=
Signature: wimse=:L0xn/2/XncJ0QYNYuwvPsDGkJ6Gbe+rFA9soJlDfXcsqEfC7enVXFIHqCGJM7gtG6kukZUw0j/YaSXmDOiaZCQ==:
Signature-Input: wimse=("@method" "@request-target" "authorization");created=1718102553;expires=1718102853;nonce="abcd1111";tag="wimse-service-to-service"

~~~

Assuming that the workload being called has the following keypair:

~~~ jwk
{
 "kty":"OKP",
 "crv":"Ed25519",
 "x":"CfaY1XX-aHJpenRP8ATm3yGlbcKA_treqOfwKrilwyg",
 "d":"fycSKS-iHZ6TC1BNwN6cE0sOBP3-4KgR-eqxNpnyhws"
}
~~~

A signed response would be:

~~~ http
HTTP/1.1 404 Not Found
Connection: close
Content-Type: text/plain
Signature: wimse=:tYjoiuZ3hm7Z6j4xoJKjutgNMvsag1TwaxPQk+eKNG0GsjAnNRsNz66DybN/2aCWoFkEsji2fH8uNegZrHLaBg==:
Signature-Input: wimse=("@status" "content-type" "@method";req "@request-target";req);created=1718104175;expires=1718104477;nonce="abcd2222";tag="wimse-service-to-service"

No ice cream today.

~~~

# Using Mutual TLS for Service To Service Authentication {#mutual-tls}

# Security Considerations

TODO Security and Privacy

TLS trust assumptions, server vs mutual auth, middleboxes

# IANA Considerations

TODO IANA


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
