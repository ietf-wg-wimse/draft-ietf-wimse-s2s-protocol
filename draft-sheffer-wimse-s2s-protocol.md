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

# WIMSE Identity {#whimsical-identity}

[TODO: using a URI as an identity aligns or perhaps conflicts with SPIFFE's definition of Identity the format below is basically taken from SPIFFE, I'm not convinced that this is a good or bad idea.  Perhaps we can reuse all or most of the [SPIFFE format](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md)?]

THe WIMSE identity is represented as a URI of the format:

scheme://trustdomain/path

The scheme is TBD, likely candidates are "spiffe" to align with SPIFFE or "wimse" provide an alternative. A particular deployment may use one or the other scheme, but not both at the same time since SPIFFE only allows one URI SAN in a certificate.

The trust domain is a locally defined string that is compliant with WIMSE naming schemes. The issuer of WIMSE credentials is tied to a single trust domain. The validator of a WIMSE ID token or certificate MUST check that the issuer of the credential is permitted to issue credentials with the specified trust domains and MUST validate that there are no collisions in the list of supported trust domains.

The path is a string whose format is defined by the local deployment and is subject to the requirements defined in SPIFFE.  The purpose of the path is to identify a workload for the purposes of authorization, auditing and binding to additional information.

# Application Level Service To Service Authentication {#app-level}

## The WIMSE ID Token

## Option 1: DPoP-Inspired Authentication

## Option 2: Authentication Based on HTTP Message Signatures

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
