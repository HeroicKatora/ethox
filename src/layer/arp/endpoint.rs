//! As noted in RFC 826, arp assumes that at least the mapping and identities of the own host are
//! fully known to the resolver. Furthermore, we are expected to only keep a very small cache of
//! immediate communication hosts. To make the requests themselves we thus need to be informed
//! about missing addresses.
