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
    organization: Palo Alto Networks
    email: joe@salowey.net
 -
    ins: "Y. Rosomakho"
    name: "Yaroslav Rosomakho"
    organization: Zscaler
    email: yaroslavros@gmail.com

normative:

informative:

--- abstract

The WIMSE architecture defines authentication and authorization for software workloads in a variety of runtime environments, from the most basic ones to complex multi-service, multi-cloud, multi-tenant deployments. This document profiles a workload authentication based on X.509 Workload Identity Certificates using mutual TLS (mTLS).

--- middle

# Introduction

This document defines authentication and authorization in the context of interaction between two workloads.
This is the core component of the WIMSE architecture {{?WIMSE-ARCH=I-D.ietf-wimse-arch}}.
This document focuses on using X.509 Workload Identity Certificates as defined in {{Section 6.1 of !WIMSE-CREDS=I-D.ietf-wimse-workload-creds}} to authenticate the communication between workloads using TLS.

The use of TLS for authentication is widely deployed, however it may not be applicable to all environments.  For example, some deployments may lack the PKI infrastructure necessary to manage certificates or inter-service communication consists of multiple separate TLS hops. For these cases, other options based on Workload Identity Tokens (WIT) as defined in {{Section 5 of WIMSE-CREDS}} may be more appropriate since they are not based on X.509 certificates and are communicated at the application layer rather than the transport layer.

## Deployment Architecture and Message Flow

Refer to {{Section 1.2 of WIMSE-CREDS}} for the deployment architecture which is common to all protection options.

# Conventions and Definitions

All terminology in this document follows {{WIMSE-ARCH}}.

{::boilerplate bcp14-tagged}

# Using Mutual TLS for Workload-to-Workload Authentication {#mutual-tls}

As noted in the introduction, for many deployments, transport-level protection of application traffic using TLS is ideal.

## The Workload Identity Certificate {#to-wic}

Workload Identity Certificates are X.509 certificates that carry Workload Identifiers as described in {{Section 6.1 of WIMSE-CREDS}}.

## Workload Identity Certificate Validation {#wic-validation}

Workload Identity Certificates may be used to authenticate both the server and client side of the connection.  When validating a Workload Identity Certificate, the relying party MUST use the trust anchors configured for the trust domain in the workload identifier to validate the peer's certificate.  Other PKIX {{!INET-X509-PROFILE=RFC5280}} path validation rules apply. Workloads acting as TLS clients or servers MUST validate that the trust domain portion of the Workload Identifier in the Workload Identity Certificate matches the expected trust domain for the other side of the connection.

Servers wishing to use the Workload Identity Certificate for authorizing the client MUST require client certificate authentication in the TLS handshake. Other methods of post handshake authentication are not specified by this document.

Workload Identity Certificates used by TLS servers SHOULD have the `id-kp-serverAuth` extended key usage {{!RFC5280}} field set and Workload Identity Certificates used by TLS clients SHOULD have the `id-kp-clientAuth` extended key usage field set. A certificate that is used for both client and server connections may have both fields set. This specification does not make any other requirements beyond {{INET-X509-PROFILE}} on the contents of Workload Identity Certificates or on the certification authorities that issue workload certificates.

### Server Name Validation {#server-name}

If a WIMSE client connects to a server using a DNS hostname, the server SHOULD present a certificate containing a matching DNS Subject Alternative Name (DNS-ID), and the client MUST perform standard TLS server identity validation as specified in {{Section 6.3 of !TLS-IDENTITY=RFC9525}}.

In deployments that use Workload Identity Certificates, successful DNS hostname validation authenticates the server endpoint, while the Workload Identifier provides an additional identity that can be used for workload-specific authorization and policy decisions.

Some deployments may not use DNS names for server discovery. In such cases, the client MUST be configured with sufficient information to determine the expected workload identity of the server and the client MUST validate that identity before accepting the connection.

The authority part of a URI that is a Workload Identifier is NOT treated as a hostname as otherwise specified in {{Section 6.4 of TLS-IDENTITY}}, but rather as a trust domain as specified in {{Section 4.4 of !WIMSE-IDENTIFIER=I-D.ietf-wimse-identifier}}. The server identity is encoded in the path portion of the Workload Identifier in a deployment-specific way.

Validation of the workload identity may consist of an exact match of the trust domain and path, or may follow deployment-specific rules. The path portion of the Workload Identifier MUST always be interpreted within the context of the trust domain. In most cases it is preferable to validate the entire Workload Identifier; see {{Section 1.3 of WIMSE-CREDS}} for additional implementation guidance.

## Client Authorization Using the Workload Identity {#client-name}

The server application retrieves the Workload Identifier from the client certificate's URI subjectAltName (see {{WIMSE-CREDS}}), which in turn is obtained from the TLS layer. The identifier is used in authorization, accounting and auditing.
For example, the full Workload Identifier may be matched against ACLs to authorize actions requested by the peer and the identifier may be included in log messages to associate actions with the client workload for audit purposes.
A deployment may specify other authorization policies based on the specific details of how the Workload Identifier is constructed. The path portion of the Workload Identifier MUST always be considered in the scope of the trust domain of the Workload Identifier.

See {{Section 1.3 of WIMSE-CREDS}} for additional security implications of Workload Identifiers.

# IANA Considerations

This document does not include any IANA considerations.

# Security Considerations

This document relies on the security properties of TLS {{!TLS=I-D.ietf-tls-rfc8446bis}}, PKIX path validation {{INET-X509-PROFILE}}, and Workload Identity Certificate validation as described in {{Section 6.1 of WIMSE-CREDS}}. Implementations MUST validate the peer certificate chain, the applicable extended key usage, and the Workload Identifier according to the rules in this document before using the authenticated identity for authorization decisions.

Workload Identifiers are meaningful only within the scope of their trust domain. Authorization policies MUST NOT evaluate only the path or other sub-components of a Workload Identifier without also considering the trust domain and the trust anchor used to validate the certificate. Failure to bind the Workload Identifier to the expected trust domain and configured trust anchor can allow one trust domain to impersonate workloads from another domain.

When a server is identified by a DNS hostname, clients SHOULD authenticate the server using standard TLS DNS hostname validation as specified in {{TLS-IDENTITY}}. Workload identity validation complements, rather than replaces, DNS-based server authentication by providing an authenticated workload identity for authorization decisions. Only deployments that do not rely on DNS-based server identification should authenticate the server solely using its workload identity. Accepting any certificate issued by a trusted workload CA without validating that it represents the intended server workload would allow mis-issued or otherwise valid certificates for other workloads to be used for impersonation.

Client authentication is based on the Workload Identity Certificate presented by the TLS client. A server performing mTLS authentication MUST validate the client certificate chain, the associated trust domain, and the Workload Identifier before using that identity for authorization, accounting, or auditing. Accepting any valid client certificate from a trusted CA without checking whether the authenticated workload is authorized for the requested action can allow unintended workloads to gain access.

Workload Identity Certificates are often issued to dynamic or short-lived workloads. Deployments SHOULD use certificate lifetimes that are appropriate for the workload environment and SHOULD provide timely revocation or replacement mechanisms when workload identity, authorization, or runtime state changes. Long-lived certificates increase the impact of private key compromise and stale authorization decisions.

Private keys associated with Workload Identity Certificates MUST be protected against disclosure and unauthorized use. In particular, deployments MUST NOT share private keys across unrelated workload instances. Where possible, private keys SHOULD be generated and held in the workload runtime environment or a dedicated key protection mechanism, rather than distributed over the network.

This document specifies authentication at the TLS layer. If application traffic traverses intermediaries, gateways, service meshes, or other middleboxes that terminate and re-establish TLS, the application endpoint might not be directly authenticated to the peer workload. In such deployments, authorization decisions need to account for where TLS is terminated and whether the authenticated certificate represents the peer workload, an intermediary, or another delegated entity. Where end-to-end workload authentication context is required across such boundaries, deployments SHOULD use an application-layer WIMSE protection mechanism in addition to TLS-layer server authentication.

Client certificate authentication exposes the client workload identity to the TLS server during the handshake. Deployments should consider whether disclosure of Workload Identifiers to servers, intermediaries, or logs is acceptable for their threat model. Workload Identifiers included in certificates and audit records should avoid embedding unnecessary sensitive information.

Authorization decisions based on workload identity need to be made using the authenticated identity obtained from the validated certificate, not from unauthenticated application-layer metadata such as HTTP headers. Application-layer identity assertions can be useful for logging or context, but they MUST NOT override the identity established by mutual TLS unless protected and authorized by another mechanism.

--- back

# Document History
<cref>RFC Editor: please remove before publication.</cref>

## draft-ietf-wimse-mutual-tls-03

* Editorial: consistent capitalization of the defined terms "Workload Identifier" and "Workload Identity Certificate".

## draft-ietf-wimse-mutual-tls-02

* Improved Server Name Validation section

## draft-ietf-wimse-mutual-tls-01

* Added security considerations

## draft-ietf-wimse-mutual-tls-00

* Initial version, extracted from the draft-ietf-wimse-s2s-protocol-07 S2s draft with minimal edits.
* added security consideration for Server Name Validation

# Acknowledgments
{:numbered="false"}

We thank Yaron Sheffer, Arndt Schwenkschuster, Brian Campbell,  and Daniel Feldman for their contributions to earlier versions of this document.
