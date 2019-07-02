%%%
    Title = "DNS Zone Transfer over TLS"
    abbrev = "XFR over TLS"
    category = "std"
    docName= "draft-hzpa-dprive-xfr-over-tls-02"
    ipr = "trust200902"
    area = "Internet"
    workgroup = "dprive"
    keyword = ["DNS", "operations", "privacy"]
    date = 2019-07-02T00:00:00Z
    [pi]
    [[author]]
     initials="H."
     surname="Zhang"
     fullname="Han Zhang"
     organization = "Salesforce"
       [author.address]
       email = "hzhang@salesforce.com"
       [author.address.postal]
       city = "San Francisco, CA"
       country = "United States"
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
[@!I-D.bortzmeyer-dprive-rfc7626-bis]. Stub client to recursive resolver query
privacy has received the most attention to date. There are now standards track
documents for three encryption capabilities for stub to recursive queries and
more work going on to guide deployment of specifically DNS-over-TLS (DoT)
[@!RFC7858] and DNS-over-HTTPS (DoH) [@!RFC8484].

[@!I-D.bortzmeyer-dprive-rfc7626-bis] established that stub client DNS query
transactions are not public and needed protection, but on zone transfer [@!RFC1995] [@!RFC5936] it says
only:

"Privacy risks for the holder of a zone (the risk that someone gets the data)
are discussed in [RFC5936] and [RFC5155]."

In what way is exposing the full contents of a zone a privacy risk? The contents
of the zone could include information such as names of persons used in names of
hosts. Best practice is not to use personal information for domain names, but
many such domain names exist. There may also be regulatory, policy or other
reasons why the zone contents in full must be treated as private.

Neither of the RFCs mentioned in [@!I-D.bortzmeyer-dprive-rfc7626-bis]
contemplates the risk that someone gets the data through eavesdropping on
network connections, only via enumeration or unauthorised transfer as described
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

[@!RFC5936] specifies using TSIG [@!RFC2845] for authorization of the clients of
a zone transfer and for data integrity, but does not express any need for
confidentiality, and TSIG does not offer encryption. Some operators use SSH
tunnelling or IPSec to encrypt the transfer data. 

Because the AXFR zone transfer is typically carried out over TCP from
authoritative DNS protocol implementations, encrypting AXFR using DNS-over-TLS
[@!RFC7858] seems like a simple step forward. This document specifies how to use
DoT to prevent zone collection from zone transfers, including discussion of
approaches for IXFR, which uses UDP or TCP.

NOTE: At this point some discussion of a DSO based mechanism is included in
brackets, still to decide whether or not to include this in the -02 version or
not..

# Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP 14 [@!RFC2119] and
[@!RFC8174] when, and only when, they appear in all capitals, as shown here.

Privacy terminology is as described in Section 3 of [@!RFC6973].

DNS terminology is as described in [@!RFC8499].

DoT: DNS-over-TLS as specified in [@!RFC7858]

DoH: DNS-over-HTTPS as specified in [@!RFC8484]

# Use cases for XFR-over-TLS

* Confidentiality. Clearly using an encrypted transport for zone transfers will
  defeat zone content leakage that can occur via passive surveillance.

* Authentication. Use of single or mutual TLS authentication (in combination 
  with ACLs) can complement and potentially be an alternative to TSIG.
  
* Performance. For high rates of IXFR persistent connections could offer higher
  throughput rates. (Note this is possible in principle with TCP today. 
  TODO: Look at the details of the NSD implementation.)
  
* (Performance. For the DSO case, a subscribe/publish mechanism could be
  envisaged greatly reducing the number of messages required to perform one
  transfer.)
  
* (Security. For some network configurations it is not desirable to have port 53
  on the secondary open to an untrusted network for the sole purpose of
  receiving NOTIFYs. For the DSO case, new server initiated NOTIFY messages
  could be sent on a TLS connection to the primary initiated by the secondary
  allowing the firewall to be restricted to just allowing outgoing connections
  from secondary to primary.)

* (New command channel. For the DSO case it would be possible to include new
  'control' commands e.g. 'stop serving this zone', 'delete this zone'.)

# Connection and data flows in XFR

## AXFR

The connection flow in AXFR is a NOTIFY from the primary server to the 
secondary server, and then an AXFR request from the secondary to the 
primary after which the data flows.




# Zone Transfer with DoT - Authentication

## TSIG

## Mutual TLS 

# Session Establishment and Closing

## AXFR Sessions

The connection for AXFR via DoT SHOULD be established using port 853, as
specified in [@!RFC7858], unless there is mutual agreement between the secondary
and primary to use a port other than port 853 for DNS over TLS.

TODO: diagram of connection flow for AXFR, without and with DoT

## IXFR Sessions

[@!RFC1995] specifies that Incremental Transfer may use UDP if the entire IXFR
response can be contained in a single DNS packet, otherwise, TCP is used.

QUESTION: Given this, how should confidentiality of IXFR be provided?  

To discuss:

* should IXFR have a mode in which TCP is mandatory?  
* should IXFR have a mode in which TLS is mandatory? 
* In workloads where there are frequent IXFRs, is the persistent connection mode
that TCP-Mode would enable (as well as the retries) a benefit?

## Policies for Both AXFR and IXFR

In order to assure the confidentiality of the zone information, entire group of
servers involved in XFR (the primary and all secondaries) MUST have a consistent
policy of requiring confidentiality. If any do not, this is a weak link for
attackers to exploit. How to do this is TBD.

Additionally, the entire group of servers involved in XFR (the primary and all
secondaries) MUST have a consistent policy of requiring Strict or Opportunistic
DoT [@!RFC8310]. How to do this is TBD.

## Next Steps

Upcoming IETF Hackathon experiments will feed into this Session Establishment
and Closing section, as much about this needs exploration as well as discussion
on the mailing list.

# Performance Considerations

The details in [@!RFC7858] and [@!RFC8310] about e.g. using persistent
connections and TLS Session Resumption [@!RFC5077] are fully applicable to DNS
Zone Transfer over DoT as well.

# Implementation Considerations

TBA

# IANA Considerations

TBD

# Security Considerations

This document specifies a security measure against a DNS risk: the risk that an
attacker collects entire DNS zones through eavesdropping on clear text DNS zone
transfers. It presents a new Security Consideration for DNS. Some questions to
discuss are: should DoT in this new case be required to use only TLS 1.3 and
higher to avoid residual exposure? How should padding be used (if it should)?

# Acknowledgements

The authors thank Benno Overeinder, Shumon Huque and Tim Wicinski for review and
discussions.

# Contributors
The following contributed significantly to the document:

# Changelog

draft-hzpa-dprive-xfr-over-tls-01

* Editorial changes, updates to references.

draft-hzpa-dprive-xfr-over-tls-00

* Initial commit


{backmatter}
