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

static size_t get_ext_total_len(uint8_t nh, uint8_t hdr_ext_len_byte) {
    if (nh == IPV6_EXT_FRAGMENT) {
        return 8; // frag header is always 8 bytes fixed
    }
    // standard RFC formula: (Length Field + 1) * 8
    return (size_t) (hdr_ext_len_byte + 1) * 8;
}

static struct ipv6_ext_base parse_ipv6_ext_base(struct raw_pack_stream* rps) {
	struct ipv6_ext_base base;
	memcpy(&base, rps->stream, sizeof base);
	rps_seek(rps, 0x2);
	return base;
}

static struct ProtocolNode* parse_ipv6_ext_frag_hdr(
	struct raw_pack_stream *rps, 
	struct ipv6_ext_base base
) {
	const uint8_t* raw = rps_read_ptr(rps);

	struct ipv6_ext_frag_hdr* frag = malloc(sizeof(struct ipv6_ext_frag_hdr));
	if (frag == NULL) return NULL;

	frag->next_hdr = base.next_hdr;
	frag->reserved = 0;
	frag->frag_offset_m = ((uint16_t)raw[0] << 8) | raw[1];

	frag->identification = 
		((uint16_t)raw[2] << 24) |
		((uint16_t)raw[3] << 16) |
		((uint16_t)raw[4] << 8) |
		((uint16_t)raw[5]);

	rps_seek(rps, 6); // fragment headers' length is always 8
					  // but since base extension header consumes 2 bytes,
					  // we only seek 6 bytes

	struct ProtocolNode* ext_node = create_proto_node();
	ext_node->type = PROTO_IPV6_EXT_FRAG;
	ext_node->hdr = frag;
	return ext_node;
}

static struct ipv6_ext_hdr_chain parse_ipv6_ext_hdrs(
	struct ProtocolNode* parent, 
	struct raw_pack_stream* rps,
	uint8_t next
) {
	size_t offset = IPV6_HEADER_LEN;
	struct ProtocolNode* current = parent;

	while (is_ipv6_ext(next)) {
		struct ipv6_ext_base ext_base = parse_ipv6_ext_base(rps);
		size_t full_hdr_len = get_ext_total_len(next, ext_base.hdr_ext_len);
		struct ProtocolNode* ext_node = NULL;

		if (next == PROTO_IPV6_EXT_FRAG) {
			ext_node = parse_ipv6_ext_frag_hdr(rps, ext_base);
		}
		else {
			rps_seek(rps, full_hdr_len - 2); // skip other headers for now
		}

		if (ext_node) {
			current->next = ext_node;
			current = ext_node;
		}

		next = ext_base.next_hdr;
		offset += full_hdr_len;
	}

	struct ipv6_ext_hdr_chain chain = {
		.last_node = current,
		.next_proto = next,
		.offset = offset
	};

	return chain;
}

ProtocolNode_t* parse_ipv6_packet(struct raw_pack_stream* stream) {
	struct IPV6Header* ip_hdr = malloc(IPV6_HEADER_LEN);

	const uint8_t* raw = rps_read_ptr(stream);

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
	
	struct ProtocolNode* ip_node = create_proto_node();
	ip_node->type = PROTO_IPV6;
	ip_node->hdr = ip_hdr;

	uint8_t next = ip_hdr->next_hdr;

	rps_seek(stream, IPV6_HEADER_LEN);
	struct ipv6_ext_hdr_chain chain = parse_ipv6_ext_hdrs(ip_hdr, stream, next);

	const uint8_t* next_lyr_stream = raw + chain.offset;
	struct ProtocolNode* last_node = chain.last_node;

	if (next == IPPROTO_TCP) {
		last_node->next = parse_tcp_packet(next_lyr_stream);
	}
	else if (next == IPPROTO_UDP) {
		last_node->next = parse_udp_packet(next_lyr_stream);
	}

	return last_node;
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
