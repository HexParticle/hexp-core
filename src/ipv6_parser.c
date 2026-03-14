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

static inline uint8_t ipv6_version(const struct ipv6_header *h) {
    return (ntohl(h->ver_tc_fl) >> 28) & 0xF;
}

static inline uint8_t ipv6_traffic_class(const struct ipv6_header *h) {
    return (ntohl(h->ver_tc_fl) >> 20) & 0xFF;
}

static inline uint32_t ipv6_flow_label(const struct ipv6_header *h) {
    return ntohl(h->ver_tc_fl) & 0xFFFFF;
}

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

static struct ipv6_ext_base parse_ipv6_ext_base(struct raw_pack_stream* rps) {
	struct ipv6_ext_base base;
	memcpy(&base, rps->stream, sizeof base);
	rps_seek(rps, 0x2);
	return base;
}

static struct proto_node* parse_ipv6_ext_frag_hdr(
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

	struct proto_node* ext_node = create_proto_node();
	ext_node->type = PROTO_IPV6_EXT_FRAG;
	ext_node->hdr = frag;
	return ext_node;
}

/**
 * Parse IPV6 options extension header.
 * This function is unrefined.
 */
static struct proto_node* parse_ipv6_ext_opts_hdr(
	struct raw_pack_stream* rps, 
	struct ipv6_ext_base base
) {
	const uint8_t* raw = rps_read_ptr(rps);
	size_t length = base.hdr_ext_len; // length of the options[] field

	struct ipv6_ext_opts_hdr* opts = malloc(2 + length); // 2 bytes for next_hdr and hdr_ext_len
	if (opts == NULL) return NULL;

	opts->next_hdr = base.next_hdr;
	opts->hdr_ext_len = base.hdr_ext_len;
	memcpy(opts->options, raw, length);

	rps_seek(rps, length);

	struct proto_node* ext_node = create_proto_node();
	ext_node->type = PROTO_IPV6_EXT_DST_OPTS;
	ext_node->hdr = opts;
	return ext_node;
}

static struct ipv6_ext_hdr_chain parse_ipv6_ext_hdrs(
	struct proto_node* parent, 
	struct raw_pack_stream* rps,
	uint8_t next_proto
) {
	size_t offset = IPV6_HEADER_LEN;
	struct proto_node* current_node = parent;

	while (is_ipv6_ext(next_proto)) {
		struct ipv6_ext_base ext_base = parse_ipv6_ext_base(rps);
		struct proto_node* ext_node = NULL;

		size_t full_hdr_len = 0;

		if (next_proto == IPV6_EXT_FRAGMENT) {
        	full_hdr_len = 8; // frag header is always 8 bytes fixed
    	}
		else {
    		// standard RFC formula: (Length Field + 1) * 8
    		full_hdr_len = (size_t) (ext_base.hdr_ext_len + 1) * 8;
		}

		switch (next_proto) {
			case IPV6_EXT_FRAGMENT: {
				ext_node = parse_ipv6_ext_frag_hdr(rps, ext_base);
				break;
			}

			case IPV6_EXT_DEST_OPTS: {
				ext_node = parse_ipv6_ext_opts_hdr(rps, ext_base);
				break;
			}

			default: {
				rps_seek(rps, full_hdr_len - 2);
				ext_node = create_proto_node();
				ext_node->type = PROTO_IPV6_EXT;
				break;
			}
		}

		if (ext_node) {
			current_node->next = ext_node;
			current_node = ext_node;
		}

		next_proto = ext_base.next_hdr;
		offset += full_hdr_len;
	}

	struct ipv6_ext_hdr_chain chain = {
		.last_node = current_node,
		.next_proto = next_proto,
		.offset = offset
	};

	return chain;
}

struct proto_node* parse_ipv6_packet(struct raw_pack_stream* stream) {
	struct ipv6_header* ip_hdr = malloc(IPV6_HEADER_LEN);

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
	
	struct proto_node* ip_node = create_proto_node();
	ip_node->type = PROTO_IPV6;
	ip_node->hdr = ip_hdr;

	printf("IPv6 seek here: %zu, total length: %zu\n", IPV6_HEADER_LEN, stream->length);
	rps_seek(stream, IPV6_HEADER_LEN);

	struct ipv6_ext_hdr_chain chain = parse_ipv6_ext_hdrs(ip_node, stream, ip_hdr->next_hdr);
	struct proto_node* last_node = chain.last_node;

	if (chain.next_proto == IPPROTO_TCP) {
		last_node->next = parse_tcp_packet(stream);
	}
	else if (chain.next_proto == IPPROTO_UDP) {
		last_node->next = parse_udp_packet(stream);
	}

	return last_node;
}
