#include "verdict.h"

Ja3Info our_openssl_ja3_signature() {
    Ja3Info j;
    j.version    = "771";
    j.ciphers    = "4865,4866,4867,49195,49199,49196,49200,52393,52392,49171,49172,156,157,47,53";
    j.extensions = "0,11,10,35,22,23,13,43,45,51";
    j.groups     = "29,23,30,25,24";
    j.ec_formats = "0";
    j.ja3_hash   = "0cce74b0d9b7f8528fb2181588d23793";
    return j;
}