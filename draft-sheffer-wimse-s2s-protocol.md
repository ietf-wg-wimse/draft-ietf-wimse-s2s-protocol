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

The WIMSE ID is scoped within an issuer and therefore any sub-components (path portion of ID) are only unique within a trust domain defined by the issuer. Using a WIMSE ID without taking into account the trust domain could allow one domain to issue tokens to spoof identities in another domain.  Additionally, the trust domain must be tied to an authorized issuer cryptographic trust root through some mechanism such as a JWKS or X.509 certificate chain. The association of an issuer, trust domain and a cryptographic trust root MUST be communicated securely out of band.

<cref>TODO: Should there be a DNS name to Trust domain mapping defined or some other discovery mechanism?</cref>

## Workload ID Token and Proof of Possession

The Workload ID token (WIT) is bound to a secret cryptographic key and is always presented with a proof of possession as described in {{to-wit}}. The WIT is a general purpose token that can be presented in multiple contexts. The WIT and its PoP are only used in the application-level options, and both are not used in MTLS. The WIT MUST NOT be used as a bearer token. While this helps reduce the sensitivity of the token it is still possible that a token and its proof of possession may be captured and replayed within the PoP's lifetime. The following are some mitigations for the capture and reuse of the proof of possession (PoP):

* Preventing Eavesdropping and Interception with TLS

An attacker observing or intercepting the communication channel can view the token and its proof of possession and attempt to replay it to gain an advantage. In order to prevent this the
token and proof of possession MUST be sent over a secure, server authenticated TLS connection unless a secure channel is provided by some other mechanisms. Host name validation according
to {{mutual-tls}} MUST be performed. The WIT itself is not usable without a proof of possession.

* Limiting Proof of Possession Lifespan

The proof of possession MUST be time limited. A PoP should only be valid over the time necessary for it to be successfully used for the purpose it is needed. This will typically be on the order of minutes.  PoPs received outside their validity time MUST be rejected.

* Limiting Proof of Possession Scope

In order to reduce the risk of theft and replay the PoP should have a limited scope. For example, a PoP may be targeted for use with a specific workload and even a specific transaction to reduce the impact of a stolen PoP. In some cases a workload may wish to reuse a PoP for a period of time or have it accepted by multiple target workloads. A careful analysis is warranted to understand the impacts to the system if a PoP is disclosed allowing it to be presented by an attacker along with a captured WIT.

* Binding to a Timestamp or Nonce

A proof of possession should include information that can be used to uniquely identify it such as a unique timestamp or nonce.  This can be used by the receiver to perform basic replay protection against tokens it has already seen. Depending upon the design of the system it may be difficult to synchronize the replay cache across all token validators. In this case, if the PoP is not sufficiently scoped it may be usable with another workload.
While a fresh nonce could be included in the PoP, a mechanism for distributing a fresh challenge nonce from the validator to provide single use properties of a PoP is outside the scope of this specification.

* Binding to Sender

The POP MAY be bound to a sender such as the client identity of a TLS session or TLS channel binding parameters. The mechanisms for binding are outside the scope of this specification.

## Middle Boxes

In some deployments the WIMSE token and proof of possession may pass through multiple systems. The communication between the systems is over TLS, but the token and PoP are available in the clear at each intermediary.  While the intermediary cannot modify the token or the information within the PoP they can attempt to capture and replay the token or modify the data not protected by the PoP. Mitigations listed in the previous section can be used to provide some protection from middle boxes. Deployments should perform analysis on their situation to determine if it is appropriate to trust and allow traffic to pass through a middle box.

## Privacy Considerations

WITs and the proofs of possession may contain private information such as user names or other identities. Care should be taken to prevent the disclosure of this information. The use of TLS helps protect the privacy of WITs and proofs of possession.

WITs and certificates with WIMSE identifiers are typically associated with a workload and not a specific user, however in some deployments the workload may be associated directly to a user. While these are exceptional cases a deployment should evaluate if the disclosure of WITs or certificates can be used to track a user.


# IANA Considerations

TODO IANA


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
