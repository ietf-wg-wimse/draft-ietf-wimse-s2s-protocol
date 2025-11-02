---
title: "Workload Authentication Using Mutual TLS"
abbrev: "Workload MTLS"
category: std
docname: draft-ietf-wimse-mutual-tls-latest
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
  latest: "https://ietf-wg-wimse.github.io/draft-ietf-wimse-s2s-protocol/draft-ietf-wimsemutual-tls.html"

author:
 -
    ins: "j. Salowey"
    fullname: "Joe Salowey"
    organization: CyberArk
    email: joe@salowey.net
 -
    ins: "Y. Rosomakho"
    name: "Yaroslav Rosomakho"
    organization: Zscaler
    email: yaroslavros@gmail.com

normative:

informative:

--- abstract

The WIMSE architecture defines authentication and authorization for software workloads in a variety of runtime environments, from the most basic ones to complex multi-service, multi-cloud, multi-tenant deployments. This document profiles a workload authentication based on X.509 workload identity certificates using mutual TLS (mTLS).

--- middle

# Introduction

This document defines authentication and authorization in the context of interaction between two workloads.
This is the core component of the WIMSE architecture {{?I-D.ietf-wimse-arch}}.
This document focuses on using X.509 workload identity certificates {{!I-D.ietf-wimse-workload-creds}} to authenticate the communication between workloads using TLS.

The use of TLS for authentication is widely deployed, however it may not be applicable to all environments.  For example, some deployments may lack the PKI infrastructure necessary to manage certificates or inter-service communication consists of multiple separate TLS hops. For these cases, other options based on Workload Identity Tokens (WIT) {{!I-D.ietf-wimse-workload-creds}} may be more appropriate since they are not based on X.509 certificates and are communicated at the application layer rather than the transport layer.

## Deployment Architecture and Message Flow

Refer to Sec. 1.2 of {{I-D.ietf-wimse-workload-creds}} for the deployment architecture which is common to all three
protection options, including the one described here.

## Workload Identity Certificates

Workload identity certificates are X.509 certificates that carry workload identifiers as described in section 4.1 of {{!I-D.ietf-wimse-workload-creds}}

# Conventions and Definitions

All terminology in this document follows {{?I-D.ietf-wimse-arch}}.

{::boilerplate bcp14-tagged}

# Using Mutual TLS for Workload-to-Workload Authentication {#mutual-tls}

As noted in the introduction, for many deployments, transport-level protection of application traffic using TLS is ideal.

## The Workload Identity Certificate {#to-wic}

Workload identity certificates are X.509 certificates that carry workload identifiers as described in section 4.1 of {{!I-D.ietf-wimse-workload-creds}}

## Workload Identity Certificate Validation {#wic-validation}

Workload Identity Certificates may be used to authenticate both the server and client side of the connections.  When validating a Workload Identity Certificate, the relying party MUST use the trust anchors configured for the trust domain in the workload identity to validate the peer's certificate.  Other PKIX {{!RFC5280}} path validation rules apply. Workloads acting as TLS clients and servers MUST validate that the trust domain portion of the Workload Identity Certificate matches the expected trust domain for the other side of the connection.

Servers wishing to use the Workload Identity Certificate for authorizing the client MUST require client certificate authentication in the TLS handshake. Other methods of post handshake authentication are not specified by this document.

Workload Identity Certificates used by TLS servers SHOULD have the `id-kp-serverAuth` extended key usage {{!RFC5280}} field set and Workload Identity Certificates used by TLS clients SHOULD have the `id-kp-clientAuth` extended key usage field set. A certificate that is used for both client and server connections may have both fields set. This specification does not make any other requirements beyond {{!RFC5280}} on the contents of Workload Identity Certificates or on the certification authorities that issue workload certificates.

### Server Name Validation {#server-name}

If the WIMSE client uses a hostname to connect to the server and the server certificate contain a DNS SAN the client MUST perform standard host name validation ({{Section 6.3 of RFC9525}}) unless it is configured with the additional information necessary to perform alternate validation of the peer's workload identity.
If the client did not perform standard host name validation then the WIMSE client SHOULD further use the workload identifier to validate the server.
The host portion of the workload identifier is NOT treated as a host name as specified in section 6.4 of {{!RFC9525}} but rather as a trust domain. The server identity is encoded in the path portion of the workload identifier in a deployment specific way.
Validating the workload identity could be a simple match on the trust domain and path portions of the identifier or validation may be based on the specific details on how the identifier is constructed. The path portion of the WIMSE identifier MUST always be considered in the scope of the trust domain.
In most cases it is preferable to validate the entire workload identifier, see section 1.3 of {{!I-D.ietf-wimse-workload-creds}} for additional implementation advice.

## Client Authorization Using the Workload Identity {#client-name}

The server application retrieves the workload identifier from the client certificate subjectAltName, which in turn is obtained from the TLS layer. The identifier is used in authorization, accounting and auditing.
For example, the full workload identifier may be matched against ACLs to authorize actions requested by the peer and the identifier may be included in log messages to associate actions to the client workload for audit purposes.
A deployment may specify other authorization policies based on the specific details of how the workload identifier is constructed. The path portion of the workload identifier MUST always be considered in the scope of the trust domain.
See section 1.3 of {{!I-D.ietf-wimse-workload-creds}} on additional security implications of workload identifiers.

# IANA Considerations

This document does not include any IANA considerations.

# Security Considerations

ToDo: perhaps some discussion of certificate lifetimes and their implications, various server name validation choices, implications of middle boxes, etc.

--- back

# Document History
<cref>RFC Editor: please remove before publication.</cref>

## draft-ietf-wimse-mutual-tls-00

* Initial version, extracted from the draft-ietf-wimse-s2s-protocol-07 S2s draft with minimal edits.
* added security consideration for Server Name Validation

# Acknowledgments
{:numbered="false"}

We thank Yaron Sheffer, Arndt Schwenkschuster, Brian Campbell,  and Daniel Feldman for their contributions to earlier versions of this document.
