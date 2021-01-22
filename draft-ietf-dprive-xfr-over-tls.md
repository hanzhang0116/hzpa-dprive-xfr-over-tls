%%%
    Title = "DNS Zone Transfer-over-TLS"
    abbrev = "XFR-over-TLS"
    category = "std"
    docName= "draft-ietf-dprive-xfr-over-tls-05"
    ipr = "trust200902"
    area = "Internet"
    workgroup = "dprive"
    keyword = ["DNS", "operations", "privacy"]
    updates = [1995, 5936, 7766]
    date = 2021-01-20T00:00:00Z
    [pi]
    [[author]]
     initials="W."
     surname="Toorop"
     fullname="Willem Toorop"
     organization = "NLnet Labs"
       [author.address]
       email = "willem@nlnetlabs.nl"
       [author.address.postal]
       streets = ["Science Park 400"]
       city = "Amsterdam"
       code = "1098 XH"
       country = "The Netherlands"
    [[author]]
    initials="S."
    surname="Dickinson"
    fullname="Sara Dickinson"
    organization = "Sinodun IT"
      [author.address]
      email = "sara@sinodun.com"
      [author.address.postal]
      streets = ["Magdalen Centre", "Oxford Science Park"]
      city = "Oxford"
      code = "OX4 4GA"
      country = "United Kingdom"
    [[author]]
     initials="S."
     surname="Sahib"
     fullname="Shivan Sahib"
     organization = "Salesforce"
       [author.address]
       email = "ssahib@salesforce.com"
       [author.address.postal]
       city = "Vancouver, BC"
       country = "Canada"
    [[author]]
     initials="P."
     surname="Aras"
     fullname="Pallavi Aras"
     organization = "Salesforce"
       [author.address]
       email = "paras@salesforce.com"
       [author.address.postal]
       city = "Herndon, VA"
       country = "United States"
     toc = "yes"
     compact = "yes"
     symrefs = "yes"
     sortrefs = "yes"
     subcompact = "no"
    [[author]]
     initials="A."
     surname="Mankin"
     fullname="Allison Mankin"
     organization = "Salesforce"
       [author.address]
       email = "allison.mankin@gmail.com"
       [author.address.postal]
       city = "Herndon, VA"
       country = "United States"
%%%

.# Abstract

DNS zone transfers are transmitted in clear text, which gives attackers the
opportunity to collect the content of a zone by eavesdropping on network
connections. The DNS Transaction Signature (TSIG) mechanism is specified to
restrict direct zone transfer to authorized clients only, but it does not add
confidentiality. This document specifies the use of TLS, rather than clear text, to
prevent zone content collection via passive monitoring of zone transfers:
XFR-over-TLS (XoT). Additionally, this specification updates RFC1995,
RFC5936 and RFC7766.

{mainmatter}

# Introduction

DNS has a number of privacy vulnerabilities, as discussed in detail in
[@!RFC7626]. Stub client to recursive resolver query privacy has received the
most attention to date, with standards track documents for both DNS-over-TLS
(DoT) [@!RFC7858] and DNS-over-HTTPS (DoH) [@RFC8484], and a proposal for
DNS-over-QUIC [@I-D.ietf-dprive-dnsoquic]. There is ongoing work on DNS privacy
requirements for exchanges between recursive resolvers and authoritative
servers [@I-D.ietf-dprive-phase2-requirements] and some suggestions for how
signaling of DoT support by authoritatives might work, e.g.,
[@I-D.vandijk-dprive-ds-dot-signal-and-pin]. However there is currently no RFC
that specifically defines recursive to authoritative DNS-over-TLS (ADoT).

[@!RFC7626] established that stub client DNS query
transactions are not public and needed protection, but on zone transfer
[@!RFC1995] [@!RFC5936] it says only:

    "Privacy risks for the holder of a zone (the risk that someone
    gets the data) are discussed in [RFC5936] and [RFC5155]."

In what way is exposing the full contents of a zone a privacy risk? The
contents of the zone could include information such as names of persons used in
names of hosts. Best practice is not to use personal information for domain
names, but many such domain names exist. The contents of the zone could also
include references to locations that allow inference about location information
of the individuals associated with the zone's organization. It could also
include references to other organizations. Examples of this could be:

   * Person-laptop.example.org 
   * MX-for-Location.example.org
   * Service-tenant-from-another-org.example.org

There may also be regulatory, policy or other reasons why the zone contents in
full must be treated as private.

Neither of the RFCs mentioned in [@!RFC7626]
contemplates the risk that someone gets the data through eavesdropping on
network connections, only via enumeration or unauthorized transfer as described
in the following paragraphs.

Zone enumeration is trivially possible for DNSSEC zones which use NSEC; i.e.
queries for the authenticated denial of existences records allow a client to
walk through the entire zone contents. [@RFC5155] specifies NSEC3, a mechanism
to provide measures against zone enumeration for DNSSEC signed zones (a goal
was to make it as hard to enumerate an DNSSEC signed zone as an unsigned zone).
Whilst this is widely used, zone walking is now possible with NSEC3 due to
crypto-breaking advances. This has prompted further work on an alternative
mechanism for DNSSEC authenticated denial of existence - NSEC5
[@!I-D.vcelak-nsec5] - however questions remain over the practicality of this
mechanism.

[@RFC5155] does not address data obtained outside zone enumeration (nor does
[@!I-D.vcelak-nsec5]). Preventing eavesdropping of zone transfers (this draft)
is orthogonal to preventing zone enumeration, though they aim to protect the
same information.

[@!RFC5936] specifies using TSIG [@!RFC2845] for authorization of the clients
of a zone transfer and for data integrity, but does not express any need for
confidentiality, and TSIG does not offer encryption. Some operators use SSH
tunneling or IPSec to encrypt the transfer data.

Section 8 of the NIST guide on 'Secure Domain Name System (DNS) Deployment'
[@nist-guide] discusses restricting access for zone transfers using ACLs and TSIG
in more detail. It is noted that in all the common open source implementations
such ACLs are applied on a per query basis. Since requests typically occur on
TCP connections authoritatives must cater for accepting any TCP connection and
then handling the authentication of each XFR request individually.

Because both AXFR and IXFR zone transfers are typically carried out over TCP
from authoritative DNS protocol implementations, encrypting zone transfers
using TLS, based closely on DoT [@!RFC7858], seems like a simple step forward.
This document specifies how to use TLS as a transport to prevent zone
collection from zone transfers.

# Document work via GitHub

[THIS SECTION TO BE REMOVED BEFORE PUBLICATION] The Github repository for this
document is at https://github.com/hanzhang0116/hzpa-dprive-xfr-over-tls.
Proposed text and editorial changes are very much welcomed there, but any
functional changes should always first be discussed on the IETF DPRIVE WG (dns-privacy) mailing list.


# Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP 14 [@!RFC2119] and
[@!RFC8174] when, and only when, they appear in all capitals, as shown here.

Privacy terminology is as described in Section 3 of [@!RFC6973].

Note that in this document we choose to use the terms 'primary' and 'secondary'
for two servers engaged in zone transfers.

DNS terminology is as described in [@!RFC8499].

DoT: DNS-over-TLS as specified in [@!RFC7858]

XFR-over-TCP: Used to mean both IXFR-over-TCP [@!RFC1995] and AXFR-over-TCP [@!RFC5936].

XoT: Generic XFR-over-TLS mechanisms as specified in this document

AXoT: AXFR-over-TLS

IXoT: IXFR over-TLS

# Use Cases for XFR-over-TLS

* Confidentiality. Clearly using an encrypted transport for zone transfers will
  defeat zone content leakage that can occur via passive surveillance.

* Authentication. Use of single or mutual TLS (mTLS) authentication (in combination 
  with ACLs) can complement and potentially be an alternative to TSIG.

* Performance. Existing AXFR and IXFR mechanisms have the burden of backwards
  compatibility with older implementations based on the original specifications
  in [@!RFC1034] and [@!RFC1035]. For example, some older AXFR servers don’t
  support using a TCP connection for multiple AXFR sessions or XFRs of different
  zones because they have not been updated to follow the guidance in [@!RFC5936].
  Any implementation of XFR-over-TLS (XoT) would obviously be required to
  implement optimized and interoperable transfers as described in [@RFC5936],
  e.g., transfer of multiple zones over one connection.
  
* Performance. Current usage of TCP for IXFR is sub-optimal in some cases i.e.
  connections are frequently closed after a single IXFR.
  
## Threat model

The threat model considered here is one where the current contents and size of the zone are considered
sensitive and should be protected during transfer.

The threat model does not, however, consider the existence of a zone, the act of
zone transfer between two entities, nor the identities of the nameservers
hosting a zone (including both those acting as hidden primaries/secondaries
or directly serving the zone) as sensitive information. The proposed mechanisms
does not attempt to obscure such information. The reasons for this include:

*  much of this information can be obtained by various methods including active scanning of the DNS
*  an attacker who can monitor network traffic can relatively easily infer relations between
   nameservers simply from traffic patterns, even when some or all of the traffic is encrypted

It is noted that simply using XoT will indicate a desire by the zone owner that the contents of the zone 
remain confidential and so could be subject to blocking (e.g. via blocking of port 853) if an attacker had 
such capabilities. However this threat is likely true of any such mechanism that attempts to encrypt data 
passed between nameservers e.g. IPsec.

# Connection and Data Flows in Existing XFR Mechanisms

The original specification for zone transfers in [@RFC1034] and [@RFC1035] was
based on a polling mechanism: a secondary performed a periodic SOA query (based
on the refresh timer) to determine if an AXFR was required.

[@RFC1995] and [@!RFC1996] introduced the concepts of IXFR and NOTIFY
respectively, to provide for prompt propagation of zone updates. This has
largely replaced AXFR where possible, particularly for dynamically updated
zones.

[@RFC5936] subsequently redefined the specification of AXFR to improve
performance and interoperability.

In this document we use the phrase "XFR mechanism" to describe the entire set of
message exchanges between a secondary and a primary that concludes in a
successful AXFR or IXFR request/response. This set may or may not include

* NOTIFY messages
* SOA queries 
* Fallback from IXFR to AXFR
* Fallback from IXFR-over-UDP to IXFR-over-TCP

The term is used to encompasses the range of permutations that are possible and
is useful to distinguish the 'XFR mechanism' from a single XFR
request/response exchange.

## AXFR Mechanism

The figure below provides an outline of an AXFR mechanism including NOTIFYs.

~~~~
   Secondary                            Primary

       |              NOTIFY               |
       | <-------------------------------- |  UDP
       | --------------------------------> |
       |          NOTIFY Response          |
       |                                   |
       |                                   |
       |            SOA Request            |
       | --------------------------------> |  UDP (or part of
       | <-------------------------------- |  a TCP session)
       |           SOA Response            |
       |                                   |
       |                                   |
       |                                   |
       |            AXFR Request           | ---
       | --------------------------------> |   |
       | <-------------------------------- |   |
       |          AXFR Response 1          |   |
       |             (Zone data)           |   |
       |                                   |   |
       | <-------------------------------- |   | TCP
       |          AXFR Response 2          |   | Session
       |             (Zone data)           |   |
       |                                   |   |
       | <-------------------------------- |   |
       |          AXFR Response 3          |   |
       |             (Zone data)           | ---
       |                                   |

              Figure 1. AXFR Mechanism
              
~~~~


1. An AXFR is often (but not always) preceded by a NOTIFY (over UDP) from the
primary to the secondary. A secondary may also initiate an AXFR based on a
refresh timer or scheduled/triggered zone maintenance.

2. The secondary will normally (but not always) make a SOA query to the primary
to obtain the serial number of the zone held by the primary.

3. If the primary serial is higher than the secondaries serial (using Serial
Number Arithmetic [@RFC1982]), the secondary makes an AXFR request (over TCP)
to the primary after which the AXFR data flows in one or more AXFR responses on
the TCP connection. [@RFC5936] defines this specific step as an 'AXFR session'
i.e. as an AXFR query message and the sequence of AXFR response messages
returned for it.

[@RFC5936] re-specified AXFR providing additional guidance beyond that provided
in [@RFC1034] and [@RFC1035] and importantly specified that AXFR must use TCP
as the transport protocol.

Additionally, sections 4.1, 4.1.1 and 4.1.2 of [@RFC5936] provide improved
guidance for AXFR clients and servers with regard to re-use of TCP connections
for multiple AXFRs and AXFRs of different zones. However [@RFC5936] was
constrained by having to be backwards compatible with some very early basic
implementations of AXFR. For example, it outlines that the SOA query can also
happen on this connection. However, this can cause interoperability problems
with older implementations that support only the trivial case of one AXFR per
connection.

## IXFR Mechanism

The figure below provides an outline of the IXFR mechanism including NOTIFYs.

~~~~
   Secondary                            Primary

       |              NOTIFY               |
       | <-------------------------------- |  UDP
       | --------------------------------> |
       |          NOTIFY Response          |
       |                                   |
       |                                   |
       |            SOA Request            |
       | --------------------------------> |  UDP or TCP
       | <-------------------------------- |  
       |           SOA Response            |
       |                                   |
       |                                   |
       |                                   |
       |            IXFR Request           |
       | --------------------------------> |  UDP or TCP
       | <-------------------------------- |
       |            IXFR Response          |
       |             (Zone data)           |
       |                                   |
       |                                   | ---
       |            IXFR Request           |    |
       | --------------------------------> |    | Retry over
       | <-------------------------------- |    | TCP if 
       |            IXFR Response          |    | required
       |             (Zone data)           | ---

              Figure 1. IXFR Mechanism
              
~~~~

1. An IXFR is normally (but not always) preceded by a NOTIFY (over UDP) from the
primary to the secondary. A secondary may also initiate an IXFR based on a
refresh timer or scheduled/triggered zone maintenance.

2. The secondary will normally (but not always) make a SOA query to the primary
to obtain the serial number of the zone held by the primary.

3. If the primary serial is higher than the secondaries serial (using Serial
Number Arithmetic [@RFC1982]), the secondary makes an IXFR request to the
primary after the primary sends an IXFR response.


[@!RFC1995] specifies that Incremental Transfer may use UDP if the entire IXFR
response can be contained in a single DNS packet, otherwise, TCP is used. In
fact it says:

    "Thus, a client should first make an IXFR query using UDP."

So there may be a fourth step above where the client falls back to IXFR-over-TCP.
There may also be a fourth step where the secondary must fall back to AXFR
because, e.g., the primary does not support IXFR.

However it is noted that most widely used open source authoritative
nameserver implementations (including both [BIND](https://www.isc.org/bind/) and
[NSD](https://www.nlnetlabs.nl/projects/nsd/about/)) do IXFR using TCP by
default in their latest releases. For BIND TCP connections are sometimes used
for SOA queries but in general they are not used persistently and close after
an IXFR is completed.

## Data Leakage of NOTIFY and SOA Message Exchanges

This section attempts to presents a rationale for considering encrypting the other
messages in the XFR mechanism.

Since the SOA of the published zone can be trivially discovered by simply
querying the publicly available authoritative servers leakage of this RR is not
discussed in the following sections.

### NOTIFY

Unencrypted NOTIFY messages identify configured secondaries on the primary.

[@RFC1996] also states: 

    "If ANCOUNT>0, then the answer section represents an
    unsecure hint at the new RRset for this (QNAME,QCLASS,QTYPE).

But since the only supported QTYPE for NOTIFY is SOA, this does not pose a
potential leak.

### SOA

For hidden primaries or secondaries the SOA response leaks only the degree of lag of
any downstream secondary.

# Updates to existing specifications

For convenience, the phrase 'XFR-over-TCP' is used in this document to mean both
IXFR-over-TCP and AXFR-over-TCP and therefore statements that use it update
both [@RFC1995] and [@RFC5936], and implicitly also apply to XoT.
Differences in behavior specific to XoT are discussed in
(#xot-specification).

Both [@RFC1995] and [@RFC5936] were published sometime before TCP was
considered a first class transport for DNS. [@RFC1995], in fact, says nothing
with respect to optimizing IXFRs over TCP or re-using already open TCP
connections to perform IXFRs or other queries. Therefore, there arguably is an
implicit assumption (probably unintentional) that a TCP connection is used for
one and only one IXFR request. Indeed, several open source implementations
currently take this approach. And whilst [@RFC5936] gives guidance on
connection re-use for AXFR, it pre-dates more recent specifications describing
persistent TCP connections e.g. [@!RFC7766], [@!RFC7828] and AXFR implementations again
often make less than optimal use of open connections.

Given this, new implementations of XoT will clearly benefit from specific guidance on
TCP/TLS connection usage for XFR because this will:

* result in more consistent XoT implementations with better interoperability 
* remove any need for XoT implementations to support legacy behavior that
  XFR-over-TCP implementations have historically often supported

Therefore this document updates both the previous specifications for
XFR-over-TCP to clarify that implementations MUST use [@!RFC7766] (DNS
Transport over TCP - Implementation Requirements) to optimize the use of TCP
connections and SHOULD use [@!RFC7828] (The edns-tcp-keepalive EDNS0 Option) to
manage persistent connections.

The following sections include detailed clarifications on the updates to XFR behavior implied in
[@RFC7766] and how the use of [@!RFC7828] applies specifically to XFR
exchanges. It also discusses how IXFR and AXFR can reuse the same TCP connection.

For completeness, we also mention here the recent specification of extended DNS
error (EDE) codes [@!RFC8914]. For zone transfers, when returning REFUSED to a
zone transfer request to an 'unauthorized' client (e.g. where the client is not
listed in an ACL for zone transfers or does not sign the request with the
correct TSIG key), the extended DNS error code 18 (Prohibited) can also be sent.

## Update to RFC1995 for IXFR-over-TCP

For clarity - an IXFR-over-TCP server compliant with this specification MUST be
able to handle multiple concurrent IXoT requests on a single TCP connection
(for the same and different zones) and SHOULD send the responses as soon as
they are available, which might be out-of-order compared to the requests.

## Update to RFC5936 for AXFR-over-TCP

For clarity - an AXFR-over-TCP server compliant with this specification MUST be
able to handle multiple concurrent AXoT sessions on a single TCP connection
(for the same and different zones). The response streams for concurrent AXFRs
MAY be intermingled and AXFR-over-TCP clients compliant with this specification
MUST be able to handle this.

## Updates to RFC1995 and RFC5936 for XFR-over-TCP

### Connection reuse

As specified, XFR-over-TCP clients SHOULD re-use any existing open TCP connection when
starting any new XFR request to the same primary, and for issuing SOA queries,
instead of opening a new connection. The number of TCP connections between a
secondary and primary SHOULD be minimized (also see (#update-to-rfc7766)).

Valid reasons for not re-using existing connections might include:

* reaching a configured limit for the number of outstanding queries or XFR requests allowed on a
  single TCP connection
* the message ID pool has already been exhausted on an open connection
* a large number of timeouts or slow responses have occurred on an open
  connection
* an edns-tcp-keepalive EDNS0 option with a timeout of 0 has been received from the
  server and the client is in the process of closing the connection (see (#the-ednstcpkeepalive-edns0-option))

If no TCP connections are currently open, XFR clients MAY send SOA queries over
UDP or a new TCP connection.

### AXFRs and IXFRs on the same connection

Neither [@RFC1995] nor [@RFC5936] explicitly discuss the use of a single TCP
connection for both IXFR and AXFR requests. [@RFC5936] does make the general statement:

    "Non-AXFR session traffic can also use an open TCP connection."

We clarify here that implementations capable of both AXFR and IXFR and compliant with this specification SHOULD

*  use the same TCP connection for both AXFR and IXFR requests to the same primary
*  pipeline such request and MAY intermingle them
*  send the response(s) for each request as soon as they are available i.e. responses MAY be sent intermingled

### XFR limits

The server MAY limit the number of concurrent IXFRs, AXFRs or total XFR
transfers in progress, or from a given secondary, to protect server resources.
Servers SHOULD return SERVFAIL if this limit is hit, since it is a
transient error and a retry at a later time might succeed.

### The edns-tcp-keepalive EDNS0 Option

XFR clients that send the edns-tcp-keepalive EDNS0 option on every XFR request provide the
server with maximum opportunity to update the edns-tcp-keepalive timeout. The XFR server
may use the frequency of recent XFRs to calculate an average update rate as
input to the decision of what edns-tcp-keepalive timeout to use. If the server
does not support edns-tcp-keepalive the client MAY keep the connection open for a
few seconds ([@RFC7766] recommends that servers use timeouts of at least a few
seconds).

Whilst the specification for EDNS0  [@RFC6891]  does not specifically mention AXFRs, it does say

    "If an OPT record is present in a received request, compliant
    responders MUST include an OPT record in their respective
    responses."

We clarify here that if an OPT record is present in a received AXFR request,
compliant responders MUST include an OPT record in each of the subsequent AXFR
responses. Note that this requirement, combined with the use of
edns-tcp-keepalive, enables AXFR servers to signal the desire to close a
connection (when existing transactions have competed) due to low resources by
sending an edns-tcp-keepalive EDNS0 option with a timeout of 0 on any AXFR
response. This does not signal that the AXFR is aborted, just that the server
wishes to close the connection as soon as possible.

### Backwards compatibility

Certain legacy behaviors were noted in [@RFC5936], with provisions that
implementations may want to offer options to fallback to legacy behavior when
interoperating with servers known not to support [@RFC5936]. For purposes of
interoperability, IXFR and AXFR implementations may want to continue offering
such configuration options, as well as supporting some behaviors that were
underspecified prior to this work (e.g. performing IXFR and AXFRs on separate
connections). However, XoT implementations should have no need to do so.

## Update to RFC7766

[@RFC7766] made general implementation
recommendations with regard to TCP/TLS connection handling:

    "To mitigate the risk of unintentional server overload, DNS
    clients MUST take care to minimize the number of concurrent TCP
    connections made to any individual server. It is RECOMMENDED
    that for any given client/server interaction there SHOULD be no
    more than one connection for regular queries, one for zone
    transfers, and one for each protocol that is being used on top
    of TCP (for example, if the resolver was using TLS). However,
    it is noted that certain primary/ secondary configurations with
    many busy zones might need to use more than one TCP connection
    for zone transfers for operational reasons (for example, to
    support concurrent transfers of multiple zones)."

Whilst this recommends a particular behavior for the clients using TCP, it
does not relax the requirement for servers to handle 'mixed' traffic (regular
queries and zone transfers) on any open TCP/TLS connection. It also overlooks the
potential that other transports might want to take the same approach with regard to
using separate connections for different purposes.

This specification for XoT updates the guidance in [@RFC7766] to provide the
same separation of connection purpose (regular queries and zone transfers) for
all transports being used on top of TCP. 

Therefore, it is RECOMMENDED that for
each protocol used on top of TCP in any given client/server interaction there
SHOULD be no more than one connection for regular queries and one for zone
transfers. 

As an illustration, it could be imagined that in future such an 
interaction could hypothetically include one or all of the following:

* one TCP connection for regular queries
* one TCP connection for zone transfers
* one TLS connection for regular queries
* one TLS connection for zone transfers
* one DoH connection for regular queries
* one DoH connection for zone transfers

We provide specific details in the later sections of reasons where more than
one connection for a given transport might be required for zone transfers from
a particular client.


# XoT specification

## TLS versions

For improved security all implementations of this specification MUST use only TLS 1.3 [@!RFC8446] or later.

## Port selection

The connection for XoT SHOULD be established using port 853, as specified in
[@!RFC7858], unless there is mutual agreement between the secondary and primary
to use a port other than port 853 for XoT. There MAY be agreement to use
different ports for AXoT and IXoT, or for different zones.

## High level XoT descriptions

It is useful to note that in XoT it is the secondary that initiates
the TLS connection to the primary for a XFR request, so that in terms of
connectivity the secondary is the TLS client and the primary the TLS server.

The figure below provides an outline of the AXoT mechanism including NOTIFYs.

~~~~
   Secondary                            Primary

       |              NOTIFY               |
       | <-------------------------------- |  UDP
       | --------------------------------> |
       |          NOTIFY Response          |
       |                                   |
       |                                   |
       |            SOA Request            |
       | --------------------------------> |  UDP (or part of
       | <-------------------------------- |  a TCP/TLS session)
       |           SOA Response            |
       |                                   |
       |                                   |
       |                                   |
       |            AXFR Request           | ---
       | --------------------------------> |   |
       | <-------------------------------- |   |
       |          AXFR Response 1          |   |
       |             (Zone data)           |   |
       |                                   |   |
       | <-------------------------------- |   | TLS
       |          AXFR Response 2          |   | Session
       |             (Zone data)           |   |
       |                                   |   |
       | <-------------------------------- |   |
       |          AXFR Response 3          |   |
       |             (Zone data)           | ---
       |                                   |

              Figure 3. AXoT Mechanism
              
~~~~

The figure below provides an outline of the IXoT mechanism including NOTIFYs.

~~~~
   Secondary                            Primary

       |              NOTIFY               |
       | <-------------------------------- |  UDP
       | --------------------------------> |
       |          NOTIFY Response          |
       |                                   |
       |                                   |
       |            SOA Request            |
       | --------------------------------> |  UDP (or part of
       | <-------------------------------- |  a TCP/TLS session)
       |           SOA Response            |
       |                                   |
       |                                   |
       |                                   |
       |            IXFR Request           | ---
       | --------------------------------> |    |
       | <-------------------------------- |    |
       |            IXFR Response          |    |
       |             (Zone data)           |    |
       |                                   |    | TLS
       |                                   |    | session
       |            IXFR Request           |    |
       | --------------------------------> |    |
       | <-------------------------------- |    |
       |            IXFR Response          |    |
       |             (Zone data)           | ---

              Figure 1. IXoT Mechanism
              
~~~~

## XoT transfers

For a zone transfer between two end points to be considered protected with XoT
all XFR requests and response for that zone MUST be sent over TLS connections
where at a minimum:

* the client MUST authenticate the server by use of an authentication domain
  name using a Strict Privacy Profile as described in [@!RFC8310]
* the server MUST validate the client is authorized to request or proxy a zone transfer by
  using one or both of the following:
      * an IP based ACL (which can be either per-message or per-connection)
      * Mutual TLS (mTLS)

The server MAY also require a valid TSIG/SIG(0) signature, but this alone is
not sufficient to authenticate the client or server. 

Authentication mechanisms are discussed in full in (#authentication-mechanisms)
and the rationale for the above requirement in (#xot-authentication). Transfer
group policies are discussed in (#policies-for-both-axot-and-ixot).


## XoT connections 

The details in (#updates-to-existing-specifications) about e.g., persistent
connections and XFR message handling are fully applicable to XoT connections as
well. However any behavior specified here takes precedence for XoT.

If no TLS connections are currently open, XoT clients MAY send SOA queries over
UDP or TCP, or TLS.

## XoT vs ADoT

As noted earlier, there is currently no specification for encryption of
connections from recursive resolvers to authoritative servers. Some
authoritatives are experimenting with ADoT and opportunistic encryption has
also been raised as a possibility; it is therefore highly likely that use of
encryption by authoritative servers will evolve in the coming years. 

This raises questions in the short term,§§ with regard to TLS connection and
message handling for authoritative servers. In particular, there is likely to be
a class of authoritatives that wish to use XoT in the near future with a small
number of configured secondaries but that do wish to support DoT for regular
queries from recursive in that same time frame. These servers have to
potentially cope with probing and direct queries from recursives and from test
servers, and also potential attacks that might wish to make use of TLS to
overload the server.

[@RFC5936] clearly states that non-AXFR session traffic can use an open TCP
connection, however, this requirement needs to be re-evaluated when considering
applying the same model to XoT. Proposing that a server should also start
responding to all queries received over TLS just because it has enabled XoT
would be equivalent to defining a form of authoritative DoT. This specification
does not propose that, but it also does not prohibit servers from answering
queries unrelated to XFR exchanges over TLS. Rather, this specification
simply outlines in later sections:

* how XoT implementations should utilize EDE codes in response to queries on TLS
  connections they are not willing to answer (see (#response-rcodes))
* the operational and policy options that a XoT server operator has
  with regard to managing TLS connections and messages (see (#xot-server-connection-handling))

## Response RCODES

XoT clients and servers MUST implement EDE codes. If a XoT server receives
non-XoT traffic it is not willing to answer on a TLS connection it SHOULD
respond with the extended DNS error code 21 - Not Supported
[@!RFC8914]. XoT clients should not send any further
queries of this type to the server for a reasonable period of time (for
example, one hour) i.e., long enough that the server configuration or policy
might be updated.

Historically servers have used the REFUSED RCODE for many situations, and so
clients often had no detailed information on which to base an error or fallback
path when queries were refused. As a result the client behavior could vary
significantly. XoT servers that refuse queries must cater for the fact that
client behavior might vary from continually retrying queries regardless of
receiving REFUSED to every query, or at the other extreme clients may decide to
stop using the server over any transport. This might be because those clients are
either non-XoT clients or do not implement EDE codes.

## AXoT specifics

### Padding AXoT responses

The goal of padding AXoT responses would be two fold:

* to obfuscate the actual size of the transferred zone to minimize information
  leakage about the entire contents of the zone.
* to obfuscate the incremental changes to the zone between SOA updates to
  minimize information leakage about zone update activity and growth.

Note that the re-use of XoT connections for transfers of multiple different
zones complicates any attempt to analyze the traffic size and timing to
extract information.

It is noted here that, depending on the padding policies eventually developed for XoT,
the requirement to obfuscate the total zone size might
require a server to create 'empty' AXoT responses. That is, AXoT responses that
contain no RR's apart from an OPT RR containing the EDNS(0) option for padding.
For example, without this capability the maximum size that a tiny zone could be padded to would 
theoretically be limited if there had to be a minimum of 1 RR per packet. 

However, as with existing AXFR, the last AXoT response message sent MUST
contain the same SOA that was in the first message of the AXoT response series
in order to signal the conclusion of the zone transfer.

[@RFC5936] says:

    "Each AXFR response message SHOULD contain a sufficient number
    of RRs to reasonably amortize the per-message overhead, up to
    the largest number that will fit within a DNS message (taking
    the required content of the other sections into account, as
    described below)."

'Empty' AXoT responses generated in order to meet a padding requirement will be
exceptions to the above statement. For flexibility, future proofing and in
order to guarantee support for future padding policies, we state here that
secondary implementations MUST be resilient to receiving padded AXoT responses,
including 'empty' AXoT responses that contain only an OPT RR containing the
EDNS(0) option for padding.

Recommendation of specific policies for padding AXoT responses are out of scope
for this specification. Detailed considerations of such policies and the
trade-offs involved are expected to be the subject of future work.


## IXoT specifics

### Condensation of responses

[@RFC1995] says condensation of responses is optional and MAY be done. Whilst
it does add complexity to generating responses it can significantly reduce the
size of responses. However any such reduction might be offset by increased
message size due to padding. This specification does not update the optionality
of condensation for XoT responses.

### Fallback to AXFR

Fallback to AXFR can happen, for example, if the server is not able to provide
an IXFR for the requested SOA. Implementations differ in how long they store
zone deltas and how many may be stored at any one time.

Just as with IXFR-over-TCP, after a failed IXFR a IXoT client SHOULD request
the AXFR on the already open XoT connection.


### Padding of IXoT responses

The goal of padding IXoT responses would be to obfuscate the incremental
changes to the zone between SOA updates to minimize information leakage about
zone update activity and growth. Both the size and timing of the IXoT responses could
reveal information.

IXFR responses can vary in size greatly from the order of 100 bytes for one or
two record updates, to tens of thousands of bytes for large dynamic DNSSEC
signed zones. The frequency of IXFR responses can also depend greatly on if and
how the zone is DNSSEC signed. 

In order to guarantee support for future padding policies, we state here that
secondary implementations MUST be resilient to receiving padded IXoT responses.

Recommendation of specific policies for padding IXoT responses are out of scope
for this specification. Detailed considerations of such policies and the
trade-offs involved are expected to be the subject of future work.

## Name compression and maximum payload sizes

It is noted here that name compression [@RFC1035] can be used in XFR responses
to reduce the size of the payload, however the maximum value of the offset that
can be used in the name compression pointer structure is 16384. For some DNS
implementations this limits the size of an individual XFR response used in
practice to something around the order of 16kB. In principle, larger
payload sizes can be supported for some responses with more sophisticated
approaches (e.g. by pre-calculating the maximum offset required).

Implementations may wish to offer options to disable name compression for XoT
responses to enable larger payloads. This might be particularly helpful when
padding is used since minimizing the payload size is not necessarily a useful
optimization in this case and disabling name compression will reduce the
resources required to construct the payload.

# Multi-primary Configurations

Also known as multi-master configurations this model can provide flexibility
and redundancy particularly for IXFR. A secondary will receive one or more
NOTIFY messages and can send an SOA to all of the configured primaries. It can
then choose to send an XFR request to the primary with the highest SOA (or
other criteria, e.g., RTT).

When using persistent connections the secondary may have a XoT connection
already open to one or more primaries. Should a secondary preferentially
request an XFR from a primary to which it already has an open XoT connection
or the one with the highest SOA (assuming it doesn't have a connection open to
it already)?

Two extremes can be envisaged here. The first one can be considered a 'preferred
primary connection' model. In this case the secondary continues to use one
persistent connection to a single primary until it has reason not to. Reasons
not to might include the primary repeatedly closing the connection, long RTTs on
transfers or the SOA of the primary being an unacceptable lag behind the SOA of
an alternative primary.

The other extreme can be considered a 'parallel primary connection' model. Here
a secondary could keep multiple persistent connections open to all available
primaries and only request XFRs from the primary with the highest serial number.
Since normally the number of secondaries and primaries in direct contact in a
transfer group is reasonably low this might be feasible if latency is the most
significant concern.

Recommendation of a particular scheme is out of scope of this document but
implementations are encouraged to provide configuration options that allow
operators to make choices about this behavior.

# Authentication mechanisms

To provide context to the requirements in section (#xot-transfers), this
section provides a brief summary of some of the existing authentication and
validation mechanisms (both transport independent and TLS specific) that are
available when performing zone transfers. 
(#xot-authentication) then discusses in more details specifically how a
combination of TLS authentication, TSIG and IP based ACLs interact for XoT.

We classify the mechanisms based on the following properties:

* 'Data Origin Authentication' (DO): Authentication that the DNS message originated
  from the party with whom credentials were shared, and of the data integrity
  of the message contents (the originating party may or may not be party
  operating the far end of a TCP/TLS connection in a 'proxy' scenario).

* 'Channel Confidentiality' (CC): Confidentiality of the communication channel between the
  client and server (i.e. the two end points of a TCP/TLS connection) from passive surveillance.

* 'Channel Authentication' (CA): Authentication of the identity of party to whom a TCP/TLS
  connection is made (this might not be a direct connection between the primary
  and secondary in a proxy scenario).

## TSIG

TSIG [@RFC2845] provides a mechanism for two or more parties to use shared
secret keys which can then be used to create a message digest to protect
individual DNS messages. This allows each party to authenticate that a request
or response (and the data in it) came from the other party, even if it was
transmitted over an unsecured channel or via a proxy. 

Properties: Data origin authentication

## SIG(0)

SIG(0) [@RFC2931] similarly also provides a mechanism to digitally sign a DNS
message but uses public key authentication, where the public keys are stored in
DNS as KEY RRs and a private key is stored at the signer. 

Properties: Data origin authentication

## TLS

### Opportunistic TLS

Opportunistic TLS for DoT is defined in [@RFC8310] and can provide a defense against passive
surveillance, providing on-the-wire confidentiality. Essentially

* clients that know authentication information for a server SHOULD try to authenticate the server
* however they MAY fallback to using TLS without authentication and 
* they MAY fallback to using cleartext if TLS is not available.

As such it does not offer a defense against active attacks (e.g. a MitM attack
on the connection from client to server), and is not considered as useful for XoT.

Properties: None guaranteed. 

### Strict TLS

Strict TLS for DoT [@RFC8310] requires that a client is configured with an
authentication domain name (and/or SPKI pinset) that MUST be used to
authenticate the TLS handshake with the server. If authentication of the server
fails, the client will not proceed with the connection. This provides a defense
for the client against active surveillance, providing client-to-server
authentication and end-to-end channel confidentiality.  

Properties: Channel confidentiality and authentication (of the server).

### Mutual TLS

This is an extension to Strict TLS [@RFC8310] which requires that a client is
configured with an authentication domain name (and/or SPKI pinset) and a client
certificate. The client offers the certificate for authentication by the server
and the client can authentic the server the same way as in Strict TLS. This
provides a defense for both parties against active surveillance, providing
bi-directional authentication and end-to-end channel confidentiality.

Properties: Channel confidentiality and mutual authentication.

## IP Based ACL on the Primary

Most DNS server implementations offer an option to configure an IP based Access
Control List (ACL), which is often used in combination with TSIG based ACLs to
restrict access to zone transfers on primary servers on a per query basis.

This is also possible with XoT but it must be noted that, as with TCP, the
implementation of such an ACL cannot be enforced on the primary until an XFR
request is received on an established connection.

As discussed in (#xot-server-connection-handling) an IP based per connection ACL
could also be implemented where only TLS connections from recognized
secondaries are accepted.

Properties: Channel authentication of the client.

## ZONEMD

For completeness, we also describe Message Digest for DNS Zones (ZONEMD)
[@?I-D.ietf-dnsop-dns-zone-digest] here. The message digest
is a mechanism that can be used to verify the content of a standalone zone. It
is designed to be independent of the transmission channel or mechanism, allowing
a general consumer of a zone to do origin authentication of the entire zone
contents. Note that the current version of [@?I-D.ietf-dnsop-dns-zone-digest]
states:

`As specified herein, ZONEMD is impractical for large, dynamic zones due to the
time and resources required for digest calculation. However, The ZONEMD record
is extensible so that new digest schemes may be added in the future to support
large, dynamic zones.`

It is complementary but orthogonal the above mechanisms; and can be used in
conjunction with XoT but is not considered further here.

# XoT authentication

It is noted that zone transfer scenarios can vary from a simple single
primary/secondary relationship where both servers are under the control of a
single operator to a complex hierarchical structure which includes proxies and
multiple operators. Each deployment scenario will require specific analysis to
determine which combination of authentication methods are best suited to the
deployment model in question.

The XoT authentication requirement specified in (#xot-transfers) addresses the
issue of ensuring that the transfers is encrypted between the two endpoints
directly involved in the current transfers. The following table summarized the
properties of a selection of the mechanisms discussed in
(#authentication-mechanisms). The two letter acronyms for the properties are
used below and (S) indicates the secondary and (P) indicates
the primary.

Method               |  DO(S) | CC(S) | CA(S) |  DO(P) | CC(P) | CA(P)
:----------------------|:---------:|:--------:|:--------:|:---------:|:-----------:|:--:
Strict TLS            |             |    Y     |     Y    |             |      Y      |
Mutual TLS          |             |     Y    |     Y    |             |      Y      |   Y
ACL on primary   |             |           |            |            |               |   Y
TSIG                   |        Y   |           |            |     Y     |               |

Table 1: Properties of Authentication methods for XoT

Based on this analysis it can be seen that:

* Using just mutual TLS can be considered a standalone solution since both end points are authenticated
  
* Using Strict TLS and an IP based ACL on the primary also provides authentication of both end points

* Additional use of TSIG (or equally SIG(0)) can also provide data origin
  authentication which might be desirable for deployments that include a proxy
  between the secondary and primary, but is not part of the XoT requirement
  because it does nothing to guarantee channel confidentiality or
  authentication.

# Policies for Both AXoT and IXoT

Whilst the protection of the zone contents in a transfer between two end points
can be provided by the XoT protocol, the protection of all the transfers of a
given zone requires operational administration and policy management.

We call the entire group of servers involved in XFR for a particular set of
zones (all the primaries and all the secondaries) the 'transfer group'.

Within any transfer group both AXFRs and IXFRs for a zone MUST all use the
same policy, e.g., if AXFRs use AXoT all IXFRs MUST use IXoT.

In order to assure the confidentiality of the zone information, the entire
transfer group MUST have a consistent policy of requiring confidentiality. If
any do not, this is a weak link for attackers to exploit.

An individual zone transfer is not considered protected by XoT unless
both the client and server are configured to use only XoT and the overall zone
transfer is not considered protected until all members of the transfer group
are configured to use only XoT with all other transfers servers (see (#implementation-considerations)). 

A XoT policy should specify

* What kind of TLS is required (Strict or Mutual TLS)
* or if an IP based ACL is required.
* (optionally) if TSIG/SIG(0) is required

Since this may require configuration of a number of servers who may be under
the control of different operators the desired consistency could be hard to
enforce and audit in practice.

Certain aspects of the Policies can be relatively easily tested independently,
e.g., by requesting zone transfers without TSIG, from unauthorized IP addresses
or over cleartext DNS. Other aspects such as if a secondary will accept data
without a TSIG digest or if secondaries are using Strict as opposed to
Opportunistic TLS are more challenging.

The mechanics of co-ordinating or enforcing such policies are out of the scope
of this document but may be the subject of future operational guidance.

# Implementation Considerations

Server implementations may want to also offer options that allow ACLs on a zone
to specify that a specific client can use either XoT or TCP. This would allow
for flexibility while clients are migrating to XoT. 

Client implementations may similarly want to offer options to cater for the
multi-primary case where the primaries are migrating to XoT. 

Such configuration options MUST only be used in a 'migration mode' though, and
therefore should be used with care.

# Implementation Status

1. The 1.9.2 version of
[Unbound](https://github.com/NLnetLabs/unbound/blob/release-1.9.2/doc/Changelog)
 includes an option to perform AXoT (instead of AXFR-over-TCP). 

2. There are currently open pull requests against NSD to implement
    1. Connection re-use by default during [XFR-over-TCP](https://github.com/NLnetLabs/nsd/pull/145)
    2. Client side [XFR-over-TLS](https://github.com/NLnetLabs/nsd/pull/149)
    
3. Version 9.17.7 of BIND contained an initial implementation of DoT, implementation of XoT is planned for early [2021](https://gitlab.isc.org/isc-projects/bind9/-/issues/1784)

Both items 1. and 2.2. listed above require the client (secondary) to
authenticate the server (primary) using a configured authentication domain name
if XoT is used.

It is noted that use of a TLS proxy in front of the primary server is a simple
deployment solution that can enable server side XoT.

# IANA Considerations

None.

# Security Considerations

This document specifies a security measure against a DNS risk: the risk that an
attacker collects entire DNS zones through eavesdropping on clear text DNS zone
transfers. 

This does not mitigate:

* the risk that some level of zone activity might be inferred by observing zone
  transfer sizes and timing on encrypted connections (even with padding
  applied), in combination with obtaining SOA records by directly querying
  authoritative servers.
* the risk that hidden primaries might be inferred or identified via
  observation of encrypted connections.
* the risk of zone contents being obtained via zone enumeration techniques.

Security concerns of DoT are outlined in [@RFC7858] and [@RFC8310].

# Acknowledgements

The authors thank Tony Finch, Peter van Dijk, Benno Overeinder, Shumon Huque
and Tim Wicinski for review and discussions.


# Contributors

Significant contributions to the document were made by:

   Han Zhang \
   Salesforce\
   San Francisco, CA\
   United States\

   Email: hzhang@salesforce.com

# Changelog

draft-ietf-dprive-xfr-over-tls-05

* Remove the open questions that received no comments.
* Add more detail to the implementation section


draft-ietf-dprive-xfr-over-tls-04

* Add Github repository
* Fix typos and references and improve layout.

draft-ietf-dprive-xfr-over-tls-03

* Remove propose to use ALPN
* Clarify updates to both RFC1995 and RFC5936 by adding specific sections on this
* Add a section on the threat model
* Convert all SVG diagrams to ASCII art
* Add discussions on concurrency limits
* Add discussions on Extended DNS error codes 
* Re-work authentication requirements and discussion
* Add appendix discussion TLS connection management

draft-ietf-dprive-xfr-over-tls-02

* Significantly update descriptions for both AXoT and IXoT for message and
  connection handling taking into account previous specifications in more detail
* Add use of APLN and limitations on traffic on XoT connections.
* Add new discussions of padding for both AXoT and IXoT
* Add text on SIG(0)
* Update security considerations
* Move multi-primary considerations to earlier as they are related to connection
  handling

draft-ietf-dprive-xfr-over-tls-01

* Minor editorial updates
* Add requirement for TLS 1.3. or later

draft-ietf-dprive-xfr-over-tls-00

* Rename after adoption and reference update.
* Add placeholder for SIG(0) discussion
* Update section on ZONEMD

draft-hzpa-dprive-xfr-over-tls-02

* Substantial re-work of the document.

draft-hzpa-dprive-xfr-over-tls-01

* Editorial changes, updates to references.

draft-hzpa-dprive-xfr-over-tls-00

* Initial commit


<reference anchor='nist-guide'
 target='https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-81-2.pdf'>
    <front>
        <title>Secure Domain Name System (DNS) Deployment Guide</title>
        <author initials='R.' surname='Chandramouli' fullname='Ramaswamy Chandramouli'>
            <organization>NIST</organization>
        </author>
        <author initials='S.' surname='Rose' fullname='Scott Rose'>
            <organization>NIST</organization>
        </author>
        <date year='2013'/>
    </front>
</reference>

<!--These lines are needed to generate references for citations that appear only
in the appendix-->
[-@?I-D.ietf-tls-esni]

{backmatter}

# XoT server connection handling

For completeness, it is noted that an earlier version of the specification
suggested using a XoT specific ALPN to negotiate TLS connections that supported
only a limited set of queries (SOA, XRFs) however this did not gain support.
Reasons given included additional code complexity and proxies having no natural
way to forward the ALPN signal to DNS nameservers over TCP connections.

## Only listen on TLS on a specific IP address

Obviously a nameserver which hosts a zone and services queries for the zone on
an IP address published in an NS record may wish to use a separate IP address
for listening on TLS for XoT, only publishing that address to its secondaries.

Pros: Probing of the public IP address will show no support for TLS. ACLs will
prevent zone transfer on all transports on a per query basis.

Cons: Attackers passively observing traffic will still be able to observe TLS
connections to the separate address.

## Client specific TLS acceptance

Primaries that include IP based ACLs and/or mutual TLS in their authentication models
have the option of only accepting TLS connections from authorized clients. This
could be implemented using a proxy or directly in DNS implementation.

Pros: Connection management happens at setup time. The maximum number of TLS
connections a server will have to support can be easily assessed. Once the
connection is accepted the server might well be willing to answer any query on
that connection since it is coming from a configured secondary and a specific
response policy on the connection may not be needed (see below).

Cons: Currently, none of the major open source DNS authoritative
implementations support such an option.

## SNI based TLS acceptance

Primaries could also choose to only accept TLS connections based on an SNI that
was published only to their secondaries. 

Pros: Reduces the number of accepted connections.

Cons: As above. For SNIs sent in the clear, this would still allow attackers
passively observing traffic to potentially abuse this mechanism. The use of
Encrypted Client Hello [@I-D.ietf-tls-esni] may be of use here.

##  TLS specific response policies

Some primaries might rely on TSIG/SIG(0) combined with per-query IP based
ACLs to authenticate secondaries. In this case the primary must accept all
incoming TLS connections and then apply a TLS specific response policy on a per
query basis.

As an aside, whilst [@RFC7766] makes a general purpose distinction to clients
in the usage of connections (between regular queries and zone transfers) this is
not strict and nothing in the DNS protocol prevents using the same connection
for both types of traffic. Hence a server cannot know the intention of any
client that connects to it, it can only inspect the messages it receives on
such a connection and make per query decisions about whether or not to answer
those queries.

Example policies a XoT server might implement are:

* strict: REFUSE all queries on TLS connections except SOA and authorized XFR requests 
* moderate: REFUSE all queries on TLS connections until one is received that is
  signed by a recognized TSIG/SIG(0) key, then answer all queries on the
  connection after that
* complex: apply a heuristic to determine which queries on a TLS connections to REFUSE
* relaxed: answer all non-XoT queries on all TLS connections with the same policy applied to TCP queries

Pros: Allows for flexible behavior by the server that could be changed over time. 

Cons: The server must handle the burden of accepting all TLS connections just
to perform XFRs with a small number of secondaries. Client behavior to REFUSED
response is not clearly defined (see below). Currently, none of the major open
source DNS authoritative implementations offer an option for different response
policies in different transports (but could potentially be implemented using a proxy).

### SNI based response policies

In a similar fashion, XoT servers might use the presence of an SNI in the
client hello to determine which response policy to initially apply to the TLS
connections. 

Pros: This has to potential to allow a clean distinction between a XoT service
and any future DoT based service for answering recursive queries.

Cons: As above.
