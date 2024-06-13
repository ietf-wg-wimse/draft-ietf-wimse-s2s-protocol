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

# Using Mutual TLS for Service To Service Authentication {#mutual-tls}

# Security Considerations

## WIMSE Identity

The WIMSE ID is scoped within a trust domain and therefore any sub components (path portion of ID) are only unique within a trust domain. Using a WIMSE ID sub components without taking into account the trust domain could allow one domain to issue tokens to spoof identities in another domain.  Additionally, the trust domain must be tied to an authorized trusted key through some mechanism such as a JWKS or X.509 certificate chain. The association of a trust domain and a cryptographic trust root MUST be communicated securely out of band.

[TODO: Should there be a DNS name to Trust domain mapping defined?]

## WIMSE ID Token and Proof of Possession

The WIMSE ID token is bound to a secret cryptographic key and is always presented with a proof of possession as described in section TBD. The ID Token and its PoP are only used in the application-level options, and both are not used in MTLS. The ID token MUST NOT be used as a bearer token. While this helps reduce the sensitivity of the token it is still possible that a token and its proof of possession may be captured and replayed.  If this risk is mitigated then WIMSE ID tokens may be resued for a period of time with fresh proofs generated for each transaction.  The following are some mitigations for the capture and reuse of the proof of possession (POP):

* Preventing Eavesdropping and Interception with TLS

An attacker observing or intercepting the communication channel can view the token and its proof of possession and attempt to replay it to gain an advantage. In order to prevent this the
token and proof of possession MUST be sent over a secure, server authenticated TLS connection unless a secure channel is provided by some other mechanisms. Host name validation according
to section TBD MUST be performed. The WIMSE ID token itself is not usable without a proof of possession.

* Limiting Proof of Possession Lifespan

The proof of possession MUST be time limited. A POP should only be valid over the time necessary for it to be successfully used for the purpose it is needed. This will typically be on the order of minutes.  POPs received outside their validity time MUST be rejected.

* Limiting Proof of Possession Scope

The POP MUST have a limited scope. Limitations on scope include constraining the POP to certain receivers and constraining the POP to a usage or transaction.

* Binding to a Nonce

A nonce MAY included in the POP to limit the possibility of replay as defined in section TBD.  The POP MAY be bound to a fresh nonce to provide single use properties.  A mechanism for distributing a fresh challenge nonce to provide single use properties of a POP is outside the scope of this specification.

* Binding to Sender

The POP MAY be bound to a sender such as the client identity of a TLS session or TLS channel binding parameters. The mechanisms for binding are outside the scope of this specification.

## Middle Boxes

In some deployments the WIMSE token and proof of possession may pass through multiple systems. The communication between the systems is over TLS, but the token and POP are available in the clear at each intermediary.  While the intermediary cannot modify the token or the information within the POP they can attempt to capture and replay the token or modify the data not protected by the POP. Mitigations listed in the previous section can be used to provide some protection from middle boxes. Deployments should perform analysis on their situation to determine if it is appropriate to trust and allow traffic to pass through a middle box.

## Privacy Considerations

WIMSE tokens and the proofs of possession may contain private information such as user names or other identities. Care should be taken to prevent the disclosure of this information. The use of TLS helps protect the privacy of WIMSE tokens and proofs of possession.

WIMSE tokens are typically associated with a workload that is not directly associated with a user, however in some deployments the workload may be associated directly to a user. In these cases the WIMSE token can be used to track the user if it is disclosed in clear text.

If the WIMSE ID is used with X.509 certificates then the workload identity may be disclosed as part of the TLS handshake.  This can be partially mitigated by using TLS 1.3 to protect the client and server identities.


# IANA Considerations

TODO IANA


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
