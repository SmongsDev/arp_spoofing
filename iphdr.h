#pragma once

#include <cstdint>
#include <arpa/inet.h>
#include "ip.h"

#pragma pack(push, 1)
struct IpHdr final {
    uint8_t ver_hlen_;    // Version (4 bits) + Header length (4 bits)
    uint8_t tos_;         // Type of service
    uint16_t tlen_;       // Total length
    uint16_t id_;         // Identification
    uint16_t flags_frag_; // Flags (3 bits) + Fragment offset (13 bits)
    uint8_t ttl_;         // Time to live
    uint8_t proto_;       // Protocol
    uint16_t chksum_;     // Header checksum
    uint32_t sip_;        // Source IP
    uint32_t dip_;        // Destination IP

    // Getters
    uint8_t ver() { return (ver_hlen_ & 0xF0) >> 4; }
    uint8_t hlen() { return ver_hlen_ & 0x0F; }
    uint16_t tlen() { return ntohs(tlen_); }
    uint16_t id() { return ntohs(id_); }
    uint8_t flags() { return (ntohs(flags_frag_) & 0xE000) >> 13; }
    uint16_t frag_offset() { return ntohs(flags_frag_) & 0x1FFF; }
    uint8_t ttl() { return ttl_; }
    uint8_t proto() { return proto_; }
    uint16_t chksum() { return ntohs(chksum_); }
    Ip sip() { return ntohl(sip_); }
    Ip dip() { return ntohl(dip_); }

    // Protocol types
    enum: uint8_t {
        ICMP = 1,
        IGMP = 2,
        TCP = 6,
        UDP = 17,
        ENCAP = 41,
        OSPF = 89,
        SCTP = 132
    };

    // IP flags
    enum: uint16_t {
        RF = 0x8000,      // Reserved Fragment Flag
        DF = 0x4000,      // Don't Fragment Flag
        MF = 0x2000       // More Fragments Flag
    };
};
typedef IpHdr *PIpHdr;
#pragma pack(pop)
