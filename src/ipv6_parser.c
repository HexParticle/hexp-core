/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2023 Kagati Foundation
 */

#include "ipv6_parser.h"
#include "ipv4_parser.h"
#include "udp_parser.h"
#include "tcp_parser.h"
#include "ip.h"

#include <string.h>

static inline int is_ipv6_ext(uint8_t nh) {
    switch (nh) {
        case IPV6_EXT_HOP_BY_HOP:
        case IPV6_EXT_ROUTING:
        case IPV6_EXT_FRAGMENT:
        case IPV6_EXT_ESP:
        case IPV6_EXT_AUTH_HDR:
        case IPV6_EXT_DEST_OPTS:
            return 1;
        default:
            return 0;
    }
}

static IPV6ExtHeaderChain_t parse_ipv6_ext_hdrs(ProtocolNode_t* parent, const uint8_t* raw, uint8_t next) {
	size_t offset = IPV6_HEADER_LEN;
	ProtocolNode_t* current = parent;

	while (is_ipv6_ext(next)) {
		const IPV6ExtHeader_t* ext = malloc(sizeof(IPV6ExtHeader_t));
		memcpy(ext, raw + offset, sizeof(IPV6ExtHeader_t));

		size_t ext_len;
		if (ext->next_hdr == IPV6_EXT_FRAGMENT) {
			ext_len = 8; // always 8
		}
		else {
			// For more information about the following formula, visit:
			//	  https://en.wikipedia.org/wiki/IPv6_packet#Extension_headers
			ext_len = (ext->hdr_ext_len + 1) * 8;
		}

		ProtocolNode_t* ext_node = create_proto_node();
		ext_node->next = ext->next_hdr;
		ext_node->hdr = ext;
		ext_node->type = PROTO_IPV6_EXT;

		current->next = ext_node;
		current = ext_node;

		next = ext->next_hdr;
		offset += ext_len;
	}

	IPV6ExtHeaderChain_t chain = {
		.last_node = current,
		.next_proto = next,
		.offset = offset
	};

	return chain;
}

ProtocolNode_t* parse_ipv6_packet(const RawPacketStream_t* stream) {
	IPV6Header_t* ip_hdr = malloc(sizeof(IPV6Header_t));

	const uint8_t* raw = stream->stream;

	ip_hdr->ver_tc_fl = 
			((uint32_t) raw[0] << 24) |
			((uint32_t) raw[1] << 16) |
			((uint32_t) raw[2] << 8)  |
			((uint32_t) raw[3]);

	ip_hdr->len = 
			((uint32_t) raw[4] << 8) | 
			((uint32_t) raw[5]);

	ip_hdr->next_hdr = 	raw[6];
	ip_hdr->hop_limit = raw[7];
	
	memcpy(ip_hdr->src, raw + 8, IPV6_ADDR_LEN);
	memcpy(ip_hdr->dst, raw + 24, IPV6_ADDR_LEN);
	
	ProtocolNode_t* ip_node = create_proto_node();
	ip_node->type = PROTO_IPV6;
	ip_node->hdr = ip_hdr;

	uint8_t next = ip_hdr->next_hdr;
	IPV6ExtHeaderChain_t chain = parse_ipv6_ext_hdrs(ip_hdr, raw, next);

	const* next_lyr_stream = raw + chain.offset;

	if (next == IPPROTO_TCP) {
		chain.last_node->next = parse_tcp_packet(next_lyr_stream);
	}
	else if (next == IPPROTO_UDP) {
		chain.last_node->next = parse_udp_packet(next_lyr_stream);
	}

	return ip_node;
}

inline uint8_t ipv6_version(const IPV6Header_t *h) {
    return (ntohl(h->ver_tc_fl) >> 28) & 0xF;
}

inline uint8_t ipv6_traffic_class(const IPV6Header_t *h) {
    return (ntohl(h->ver_tc_fl) >> 20) & 0xFF;
}

inline uint32_t ipv6_flow_label(const IPV6Header_t *h) {
    return ntohl(h->ver_tc_fl) & 0xFFFFF;
}
