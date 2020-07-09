%%%
    Title = "DNS Zone Transfer-over-TLS"
    abbrev = "XFR-over-TLS"
    category = "std"
    docName= "draft-ietf-dprive-xfr-over-tls-02"
    ipr = "trust200902"
    area = "Internet"
    workgroup = "dprive"
    keyword = ["DNS", "operations", "privacy"]
    updates = [1995, 7766]
    date = 2020-07-01T00:00:00Z
    [pi]
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
confidentiality. This document specifies use of DNS-over-TLS to prevent zone
contents collection via passive monitoring of zone transfers.

{mainmatter}

# Introduction

DNS has a number of privacy vulnerabilities, as discussed in detail in
[@!I-D.ietf-dprive-rfc7626-bis]. Stub client to recursive resolver query
privacy has received the most attention to date. There are now standards track
documents for three encryption capabilities for stub to recursive queries and
more work going on to guide deployment of specifically DNS-over-TLS (DoT)
[@!RFC7858] and DNS-over-HTTPS (DoH) [@!RFC8484].

[@!I-D.ietf-dprive-rfc7626-bis] established that stub client DNS query
transactions are not public and needed protection, but on zone transfer
[@!RFC1995] [@!RFC5936] it says only:

"Privacy risks for the holder of a zone (the risk that someone gets the data)
are discussed in [RFC5936] and [RFC5155]."

In what way is exposing the full contents of a zone a privacy risk? The contents
of the zone could include information such as names of persons used in names of
hosts. Best practice is not to use personal information for domain names, but
many such domain names exist. There may also be regulatory, policy or other
reasons why the zone contents in full must be treated as private.

Neither of the RFCs mentioned in [@!I-D.ietf-dprive-rfc7626-bis]
contemplates the risk that someone gets the data through eavesdropping on
network connections, only via enumeration or unauthorized transfer as described
in the following paragraphs.

[@!RFC5155] specifies NSEC3 to prevent zone enumeration, which is when queries
for the authenticated denial of existences records of DNSSEC allow a client to
walk through the entire zone. Note that the need for this protection also
motivates NSEC5 [@!I-D.vcelak-nsec5]; zone walking is now possible with NSEC3
due to crypto-breaking advances, and NSEC5 is a response to this problem.

[@!RFC5155] does not address data obtained outside zone enumeration (nor does
[@!I-D.vcelak-nsec5]). Preventing eavesdropping of zone transfers (this draft)
is orthogonal to preventing zone enumeration, though they aim to protect the
same information.

[@!RFC5936] specifies using TSIG [@!RFC2845] for authorization of the clients
of a zone transfer and for data integrity, but does not express any need for
confidentiality, and TSIG does not offer encryption. Some operators use SSH
tunneling or IPSec to encrypt the transfer data.

Because the AXFR zone transfer is typically carried out over TCP from
authoritative DNS protocol implementations, encrypting AXFR using DoT
[@!RFC7858] seems like a simple step forward. This document specifies how to use
DoT to prevent zone collection from zone transfers, including discussion of
approaches for IXFR, which uses UDP or TCP.

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

XoT: Generic XFR-over-TLS mechanisms as specified in this document

AXoT: AXFR-over-TLS

IXoT: IXFR over-TLS

# Use Cases for XFR-over-TLS

* Confidentiality. Clearly using an encrypted transport for zone transfers will
  defeat zone content leakage that can occur via passive surveillance.

* Authentication. Use of single or mutual TLS authentication (in combination 
  with ACLs) can complement and potentially be an alternative to TSIG.

* Performance. Existing AXFR and IXFR mechanisms have the burden of backwards
  compatibility with older implementations based on the original specifications
  in [@RFC1034] and [@RFC1035]. For example, some older AXFR servers don’t
  support using a TCP connection for multiple AXFR sessions or XFRs of different
  zones because they have not been updated to follow the guidance in [@RFC5936].
  Any implementation of XFR-over-TLS (XoT) would obviously be required to
  implement optimized and interoperable transfers as described in [@RFC5936],
  e.g., transfer of multiple zones over one connection.
  
* Performance. Current usage of TCP for IXFR is sub-optimal in some cases i.e.
  connections are frequently closed after a single IXFR.

# Connection and Data Flows in Existing XFR Mechanisms

The original specification for zone transfers in [@RFC1034] and [@RFC1035] was
based on a polling mechanism: a secondary performed a periodic SOA query (based
on the refresh timer) to determine if an AXFR was required.

[@RFC1995] and [@RFC1996] introduced the concepts of IXFR and NOTIFY
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

[Figure 1. AXFR Mechanism](https://github.com/hanzhang0116/hzpa-dprive-xfr-over-tls/blob/02_updates/02-draft-svg/AXFR_mechanism.svg)

1. An AXFR is often (but not always) preceded by a NOTIFY (over UDP) from the
primary to the secondary. A secondary may also initiate an AXFR based on a
refresh timer or scheduled/triggered zone maintenance.

2. The secondary will normally (but not always) make a SOA query to the primary
to obtain the serial number of the zone held by the primary.

3. If the primary serial is higher than the secondaries serial (using Serial
Number Arithmetic [@RFC1982]), the secondary makes an AXFR request (over TCP)
to the primary after which the AXFR data flows in one or more AXFR responses on
the TCP connection.


[@RFC5936] specifies that AXFR must use TCP as the transport protocol but
details that there is no restriction in the protocol that a single TCP connection
must be used only for a single AXFR exchange, or even solely for XFRs. For
example, it outlines that the SOA query can also happen on this connection.
However, this can cause interoperability problems with older implementations
that support only the trivial case of one AXFR per connection.

Further details of the limitations in existing AXFR implementations are outlined
in [@RFC5936].

It is noted that unless the NOTIFY is sent over a trusted communication channel
and/or signed by TSIG is can be spoofed causing unnecessary zone transfer
attempts.

Similarly unless the SOA query is sent over a trusted communication channel
and/or signed by TSIG the response can, in principle, be spoofed causing a
secondary to incorrectly believe its version of the zone is update to date.
Repeated successful attacks on the SOA could result in a secondary serving stale
zone data.

## IXFR Mechanism

The figure below provides an outline of the IXFR mechanism including NOTIFYs.

[Figure 1. IXFR Mechanism](https://github.com/hanzhang0116/hzpa-dprive-xfr-over-tls/blob/02_updates/02-draft-svg/IXFR%20mechanism.svg)

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
fact is says in non-normative language:

"Thus, a client should first make an IXFR query using UDP."

So there may be a forth step above where the client falls back to IXFR-over-TCP.
There may also be a forth step where the secondary must fall back to AXFR
because, e.g., the primary does not support IXFR.

However it is noted that at least two widely used open source authoritative
nameserver implementations ([BIND](https://www.isc.org/bind/) and
[NSD](https://www.nlnetlabs.nl/projects/nsd/about/)) do IXFR using TCP by
default in their latest releases. For BIND TCP connections are sometimes used
for SOA queries but in general they are not used persistently and close after
an IXFR is completed.
 
<!-- QUESTION FOR US: Look at packet captures from NSD and Knot Auth to see what they do.-->

It is noted that the specification for IXFR was published well before TCP was
considered a first class transport for DNS. This document therefore updates
[@RFC1995] to state that DNS implementations that support IXFR-over-TCP MUST use
[@RFC7766] to optimize the use of TCP connections and SHOULD use [@!RFC7858] to
manage persistent connections.


## Data Leakage of NOTIFY and SOA Message Exchanges

This section attempts to presents a rationale for also encrypting the other
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

For hidden primaries or secondaries the SOA response leaks the degree of lag of
any downstream secondary.

# Connections and Data Flows in XoT

## Connection usage

### Background

It is useful to note that in these mechanisms it is the secondary that initiates
the TLS connection to the primary for a XFR request, so that in terms of
connectivity the secondary is the TLS client and the primary the TLS server.

The details in [@RFC7766], [@!RFC7858] and [@!RFC8310] about, e.g., persistent
connection and message handling are fully applicable to XoT as well. However
any special behavior specified here takes precedence for XoT.

We note that whilst [@RFC5936] already recommends re-using open TCP
connections, it does state "Non-AXFR session traffic can also use an open TCP
connection." when discussing AXFR-over-TCP. It defines an AXFR session as an
AXFR query message and the sequence of AXFR response messages returned for it.
Note that this excludes any SOA queries issued as part of the overall AXFR
mechanism. This requirement raises some issues when considering applying the
same requirement to XoT since there is no guarantee that a XoT server also
supports DoT for regular queries and it would be optimal to have the capability to
send SOA queries over an already open TLS connection.

For further context we also point out that [@RFC7766] later made general implementation recommendations with regard to TCP connection handling:

"To mitigate the risk of unintentional server overload, DNS clients MUST take
care to minimize the number of concurrent TCP connections made to any
individual server. It is RECOMMENDED that for any given client/server
interaction there SHOULD be no more than one connection for regular queries,
one for zone transfers, and one for each protocol that is being used on top of
TCP (for example, if the resolver was using TLS). However, it is noted that
certain primary/ secondary configurations with many busy zones might need to
use more than one TCP connection for zone transfers for operational reasons
(for example, to support concurrent transfers of multiple zones)."

This therefore recommends a particular behavior for the clients using TCP, but
does not relax the requirement for servers to handle 'mixed' traffic (regular
queries and zone transfers) on any open TCP connection. It also overlooks the
potential for other transports to want to take the same approach with regard to
specific purposes for separate connections.

### New guidance

This specification for XoT updates the guidance in [@RFC7766] to provide the
same separation of connection purpose (regular queries and zone transfers) for
all transports being used on top of TCP. Therefore, it is RECOMMENDED that for
each protocol used on top of TCP in any given client/server interaction there
SHOULD be no more than one connection for regular queries and one for zone
transfers. 

We provide specific details in the following sections of reasons
where more than one connection might be required for zone transfers.

For the case where the transport is TLS, the connection initiated by the client
to use primarily for regular queries can be considered a DoT connection whereas
the connection initiated by the client to use primarily for zone transfers can
be considered a XoT connection. This approach aligns with the model specified
in [@RFC7766], but it does not preclude non-XoT traffic using an open XoT
connection if both the client and server support DoT. We use the term XoT
connection in the rest of this document to indicate connections that are
initiated by the client for the primary or exclusive use for zone transfers.

Various considerations around DoT and XoT connectivity include the following:

* In practice, since the current DoT specification [@RFC7858] is limited to the
  stub to recursive path, only recursive resolvers that are also capable of
  authoritatively hosting zones would support accepting both XoT and DoT
  connections. [@RFC7858] says nothing in relation to stubs or other clients
  requesting zone transfers from recursive resolvers over DoT, or recursive
  resolvers providing them.

* Some authoritative server implementations do support DoT for regular queries
  today, but only on an experimental basis.

* Authoritative server implementations can in principle support XoT and not DoT
  but in practice they are likely to implement some form of DoT (e.g.
  non-standard, opportunistic DoT) prior to implementing XoT.

* In the absence of a signaling mechanism or specific configuration clients
  configured to request zone transfers cannot know if the configured XoT server
  also supports DoT. They also have no knowledge if it is a recursive
  implementation, and authoritative implementation or both.

 * In the absence of a signaling mechanism a server cannot know what type of
   connection (XoT vs DoT) the client intends to make. In particular if the
   first query received on a TLS connection is an SOA the server cannot
   determine the connection type. The presence of a TSIG signature on the SOA
   could be used to signal a XoT connection?

* Many authoritative servers restrict zone transfers to only authorized clients
  which are most likely also purely authoritative servers and for that case it
  is unlikely that any non-XoT traffic would be exchanged between the primary
  and secondary. However the server typically does not know if the client is
  authorized until the first XFR request is received (based on source IP or
  TSIG).


* The authentication models for DoT and XoT are likely to be different. XoT
  clients that want to use Strict DoT will be pre-configured with an authentication
  domain name for the XoT server, the details of which are not limited by this specification.
  Work is still underway to understand how authentication in ADoT will work.

## TLS versions

For improved security all implementations of this specification MUST use only TLS 1.3 [RFC8446] or later.

## AXoT mechanism

The figure below provides an outline of the AXoT mechanism including NOTIFYs.

[Figure 3: AXoT mechanism](https://github.com/hanzhang0116/hzpa-dprive-xfr-over-tls/blob/02_updates/02-draft-svg/AXoT_mechanism_1.svg)

The connection for AXoT SHOULD be established using port 853, as
specified in [@!RFC7858], unless there is mutual agreement between the secondary
and primary to use a port other than port 853 for AXoT.

### Coverage and relationship to RFC5936

[@RFC5936] re-specified AXFR providing additional guidance beyond that provided
in [@RFC1034] and [@RFC1035]. For example, sections 4.1, 4.1.1 and 4.1.2 of
[@RFC5936] provide improved guidance for AXFR clients and servers with regard to
re-use of connections for multiple AXFRs, AXFRs of different zones and using TCP
connection for other queries including SOA. However [@RFC5936] was constrained
by having to be backwards compatible with some very early basic implementations
of AXFR. 

Here we specify some optimized behaviors for AXoT, based
closely on those in [@RFC5936], but without the constraint of backwards
compatibility since it is expected that all implementations of AXoT fully
implement the behavior described here.

Where any behavior is not explicitly described here, the behavior specified in
[@RFC5936] MUST be followed. Any behavior specified here takes precedence for
AXoT implementations over that in [@RFC5936].

### AXoT connection and message handling

The first paragraph of Section 4.1.1 of [@RFC5936] says that clients SHOULD
close the connection when there is no 'apparent need' to use the connection for
some time period.

For AXoT this requirement is updated: AXoT clients and servers SHOULD use EDNS0
Keepalive [RFC7828] to establish the connection timeouts to be used. The client
SHOULD send the EDNS0 Keepalive option on every AXoT request sent so that the
server has every opportunity to update the Keepalive timeout. The AXoT server
may use the frequency of recent AXFRs to calculate an average update rate as
input to the decision of what EDNS0 Keepalive timeout to use. If the server
does not support EDNS0 Keepalive the client MAY keep the connection open for a
few seconds ([@RFC7766] recommends that servers use timeouts of at least a few
seconds).

Whilst the specification for EDNS0  [@RFC6891]  does not specifically mention AXFRs, it does say

"If an OPT record is present in a received request, compliant
   responders MUST include an OPT record in their respective responses."
 
We clarify here that if an OPT record is present in a received AXoT request,
compliant responders MUST include an OPT record in each of the subsequent AXoT
responses. Note that this requirement, combined with the use of EDNS0
Keepalive, enables AXoT servers to signal the desire to close a connection due
to low resources by sending an EDNS0 Keepalive option with a timeout of 0 on
any AXoT response (in the absence of another way to signal the abort of a AXoT
transfer).

An AXoT server MUST be able to handle multiple AXFR requests on a
single XoT connection (for the same and different zones). It MAY also handle
other query/response transactions over it if it also supports DoT.

TODO: Specify server and client behavior if other traffic not supported.

[@RFC5936] says:

    "An AXFR client MAY use an already opened TCP connection to start an
    AXFR session.  Using an existing open connection is RECOMMENDED over
    opening a new connection.  (Non-AXFR session traffic can also use an
    open connection.)"

For AXoT this requirement is restated: AXoT clients SHOULD re-use an existing
open XoT connection when starting any new AXoT session to the same primary, and
for issuing SOA queries, instead of opening a new connection. The number of XoT
connections between a secondary and primary SHOULD be minimized.

Valid reasons for not re-using existing connections might include:

* reaching a configured limit for the number of outstanding queries allowed on a
  single XoT connection
* the message ID pool has already been exhausted on an open connection
* a large number of timeouts or slow responses have occurred on an open
  connection
* an EDNS0 Keepalive option with a timeout of 0 has been received from the
  server and the client is in the process of closing the connection

If no XoT connections are currently open, AXoT clients MAY send SOA queries over
UDP, TCP or TLS.

[@RFC5936] says:

    "Some old AXFR clients expect each response message to contain only a
    single RR.  To interoperate with such clients, the server MAY
    restrict response messages to a single RR."

This is opposed to the normal behavior of containing a sufficient number of
RRs to reasonably amortize the per-message overhead. We clarify here that AXoT
clients MUST be able to handle responses that include multiple RRs, up to the
largest number that will fit within a DNS message (taking the required content
of the other sections into account, as described here and in [@RFC5936]). This
removes any burden on AXoT servers of having to accommodate a configuration
option or support for restricting responses to containing only a single RR.

An AXoT client SHOULD pipeline AXFR requests for different zones on a single XoT
connection. An AXoT server SHOULD respond to those requests as soon as the
response is available i.e. potentially out of order.

### Padding AXoT responses

The goal of padding AXoT responses would be two fold:

* to obfuscate the actual size of the transferred zone to minimize information
  leakage about the entire contents of the zone.
* to obfuscate the incremental changes to the zone between SOA updates to
  minimize information leakage about zone update activity and growth.

Note that the re-use of XoT connections for transfers of multiple different
zones complicates any attempt to analyze the traffic size and timing to
extract information.

We note here that any requirement to obfuscate the total zone size is likely to
require a server to create 'empty' AXoT responses. That is, AXoT responses that
contain no RR's apart from an OPT RR containing the EDNS(0) option for padding.
However, as with existing AXFR, the last AXoT response message sent MUST
contain the same SOA that was in the first message of the AXoT response series
in order to signal the conclusion of the zone transfer.

[@RFC5936] says:

    "Each AXFR response message SHOULD contain a sufficient number of RRs
    to reasonably amortize the per-message overhead, up to the largest
    number that will fit within a DNS message (taking the required
    content of the other sections into account, as described below)."

'Empty' AXoT responses generated in order to meet a padding requirement will be
 exceptions to the above statement. In order to guarantee support for future
padding policies, we state here that secondary implementations MUST be
resilient to receiving padded AXoT responses, including 'empty' AXoT responses
that contain only an OPT RR containing the EDNS(0) option for padding.

Recommendation of specific policies for padding AXoT responses are out of scope
for this specification. Detailed considerations of such policies and the
trade-offs involved are expected to be the subject of future work.


## IXoT mechanism

The figure below provides an outline of the IXoT mechanism including NOTIFYs.

[Figure 4: IXoT mechanism]
(https://github.com/hanzhang0116/hzpa-dprive-xfr-over-tls/blob/02_updates/02-draft-svg/IXoT_mechanism_1.svg)

The connection for IXFR-over-TLS (IXoT) SHOULD be established using port 853, as
specified in [@!RFC7858], unless there is mutual agreement between the secondary
and primary to use a port other than port 853 for IXoT.

### Coverage and relationship to RFC1995

[@RFC1995] says nothing with respect to optimizing IXFRs over TCP or re-using
already open TCP connections to perform IXFRs or other queries. Therefore,
there arguably is an implicit assumption (probably unintentional) that a TCP
connection is used for one and only one IXFR request. Indeed, several open
source implementations currently take this approach.

We provide new guidance here specific to IXoT that aligns with the guidance in
[@RFC5936] for AXFR, that in section (#axot-mechanism) for AXoT, and with that
for performant TCP/TLS usage in [@RFC7766] and [@RFC7858].

Where any behavior is not explicitly described here, the behavior specified in
[@RFC1995] MUST be followed. Any behavior specified here takes precedence for
IXoT implementations over that in [@RFC1995].


### IXoT connection and message handling

In a manner entirely analogous to that described in paragraph 2 of
(#axot-connection-and-message-handling) IXoT clients and servers SHOULD use
EDNS0 Keepalive [RFC7828] to establish the connection timeouts to be used.

An IXoT server MUST be able to handle multiple IXoT requests on a
single XoT connection (for the same and different zones). It MAY also handle
other query/response transactions over it if it also supports DoT.

TODO: Specify server and client behavior if other traffic not supported.

IXoT clients SHOULD re-use an existing open XoT connection when making any new
IXoT request to the same primary, and for issuing SOA queries, instead of
opening a new connection. The number of XoT connections between a secondary and primary
SHOULD be minimized.

Valid reasons for not re-using existing connections are the same as those
described in (#axot-connection-and-message-handling)

If no XoT connections are currently open, IXoT clients MAY send SOA queries over
UDP, TCP or TLS.

An IXoT client SHOULD pipeline IXFR requests for different zones on a single XoT
connection. An IXoT server SHOULD respond to those requests as soon as the
response is available i.e. potentially out of order.

### Condensation of responses

[@RFC1995] says condensation of responses is optional and MAY be done. Whilst
it does add complexity to generating responses it can significantly reduce the
size of responses. However any such reduction might be offset by increased message size due to padding.
This specification does not update the optionality of condensation.

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


### Fallback to AXFR

Fallback to AXFR can happen, for example, if the server is not able to provide
an IXFR for the requested SOA. Implementations differ in how long they store
zone deltas and how many may be stored at any one time.

After a failed IXFR a IXoT client SHOULD request the AXFR on the already open
XoT connection.

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

# Zone Transfer with DoT - Authentication

## TSIG

TSIG [@RFC2845] provides a mechanism for two or more parties to use shared
secret keys which can then be used to create a message digest to protect
individual DNS messages. This allows each party to authenticate that a request
or response (and the data in it) came from the other party, even if it was
transmitted over an unsecured channel or via a proxy. It provides party-to-party
data authentication, but not hop-to-hop channel authentication or
confidentiality.

## SIG(0)

SIG(0) [@RFC2535] similarly also provides a mechanism to digitally sign a DNS
message but uses public key authentication, where the public keys are stored in
DNS as KEY RRs and a private key is stored at the signer. It also provides
party-to-party data authentication, but not hop-to-hop channel authentication or
confidentiality.

## TLS

### Opportunistic

Opportunistic TLS [@RFC8310] provides a defense against passive
surveillance, providing on-the-wire confidentiality.

### Strict

Strict TLS [@RFC8310] requires that a client is configured with an
authentication domain name (and/or SPKI pinset) that should be used to
authenticate the TLS handshake with the server. This additionally provides a
defense for the client against active surveillance, providing client-to-server
authentication and end-to-end channel confidentiality.

### Mutual

This is an extension to Strict TLS [@RFC8310] which requires that a client is
configured with an authentication domain name (and/or SPKI pinset) and a client
certificate. The client offers the certificate for authentication by the server
and the client can authentic the server the same way as in Strict TLS. This
provides a defense for both parties against active surveillance, providing
bi-directional authentication and end-to-end channel confidentiality.

## IP Based ACL on the Primary

Most DNS server implementations offer an option to configure an IP based Access
Control List (ACL), which is often used in combination with TSIG based ACLs to
restrict access to zone transfers on primary servers.

This is also possible with XoT but it must be noted that as with TCP the
implementation of such an ACL cannot be enforced on the primary until a XFR
request is received on an established connection.

If control were to be any more fine-grained than this then a separate, dedicated
port would need to be agreed between primary and secondary for XoT such that
implementations would be able to refuse connections on that port to all clients
except those configured as secondaries.

## ZONEMD

Message Digest for DNS Zones (ZONEMD) [@?I-D.ietf-dnsop-dns-zone-digest] digest
is a mechanism that can be used to verify the content of a standalone zone. It
is designed to be independent of the transmission channel or mechanism, allowing
a general consumer of a zone to do origin authentication of the entire zone
contents. Note that the current version of [@?I-D.ietf-dnsop-dns-zone-digest]
states:

`As specified at this time, ZONEMD is not designed for use in large, dynamic
zones due to the time and resources required for digest calculation. The ZONEMD
record described in this document includes fields reserved for future work to
support large, dynamic zones.`

It is complementary the above mechanisms and can be used in conjunction with
XoT but is not considered further.

## Comparison of Authentication Methods

The Table below compares the properties of a selection of the above methods in
terms of what protection they provide to the secondary and primary servers
during XoT in terms of:

* 'Data Auth': Authentication that the DNS message data is signed by the party
  with whom credentials were shared (the signing party may or may not be party
  operating the far end of a TCP/TLS connection in a 'proxy' scenario). For the
  primary the TSIG on the XFR request confirms that the requesting party is
  authorized to request zone data, for the secondary it authenticates the zone
  data that is received.

* 'Channel Conf': Confidentiality of the communication channel between the
  client and server (i.e. the two end points of a TCP/TLS connection).

* Channel Auth: Authentication of the identity of party to whom a TCP/TLS
  connection is made (this might not be a direct connection between the primary
  and secondary in a proxy scenario).

It is noted that zone transfer scenarios can vary from a simple single
primary/secondary relationship where both servers are under the control of a
single operator to a complex hierarchical structure which includes proxies and
multiple operators. Each deployment scenario will require specific analysis to
determine which authentication methods are best suited to the deployment model
in question.

[Table 1: Properties of Authentication methods for XoT](https://github.com/hanzhang0116/hzpa-dprive-xfr-over-tls/blob/02_updates/02-draft-svg/Properties_of_Authentication_methods_for_XoT.svg)

Based on this analysis it can be seen that:

* A combination of Opportunistic TLS and TSIG provides both data authentication
  and channel confidentiality for both parties. However this does not stop a
  MitM attack on the channel which could be used to gather zone data.

* Using just mutual TLS can be considered a standalone solution if the
  secondary has reason to place equivalent trust in channel authentication as
  data authentication, e.g., the same operator runs both the primary and
  secondary.
  
* Using TSIG, Strict TLS and an ACL on the primary provides all 3 properties for
  both parties with probably the lowest operational overhead.

# Policies for Both AXFR and IXFR

We call the entire group of servers involved in XFR (all the primaries and all
the secondaries) the 'transfer group'.

Within any transfer group both AXFRs and IXFRs for a zone SHOULD all use the
same policy, e.g., if AXFRs use AXoT all IXFRs SHOULD use IXoT.

In order to assure the confidentiality of the zone information, the entire
transfer group MUST have a consistent policy of requiring confidentiality. If
any do not, this is a weak link for attackers to exploit. 

A XoT policy should specify

* If TSIG or SIG(0) is required
* What kind of TLS is required (Opportunistic, Strict or mTLS)
* If IP based ACLs should also be used.

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

TBD

# Implementation Status

The 1.9.2 version of
[Unbound](https://github.com/NLnetLabs/unbound/blob/release-1.9.2/doc/Changelog)
 includes an option to perform AXoT (instead of TCP). This requires
the client (secondary) to authenticate the server (primary) using a configured
authentication domain name.

It is noted that use of a TLS proxy in front of the primary server is a simple
deployment solution that can enable server side XoT.

# IANA Considerations

TBD

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

The authors thank Benno Overeinder, Shumon Huque and Tim Wicinski for review
and discussions.

# Contributors

Significant contributions to the document were made by:

   Han Zhang \
   Salesforce\
   San Francisco, CA\
   United States\

   Email: hzhang@salesforce.com

# Changelog

draft-ietf-dprive-xfr-over-tls-01

* Significantly update descriptions for both AXoT and IXoT for message and
  connection handling taking into account previous specifications in more detail
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


{backmatter}
