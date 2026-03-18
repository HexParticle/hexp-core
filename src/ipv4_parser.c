// SPDX-License-Identifier: MIT
/*
 * Copyright (c) 2023 Kagati Foundation
 */

#include "ipv4_parser.h"
#include "tcp_parser.h"
#include "proto_node.h"
#include "udp_parser.h"
#include "icmp_parser.h"
#include "ip.h"

#include <string.h>
#include <stdbool.h>

struct proto_node* parse_raw_proto_node(struct raw_pack_stream* rps) {
	const uint8_t* raw = rps_read_ptr(rps);

	size_t remain_len = rps->length - rps->read_off; // remaining length
	const uint8_t* remain_raw = malloc(remain_len); // remaining bytes
	memcpy(remain_raw, raw, remain_len);

	struct proto_node* node = create_proto_node();
	node->type = PROTO_RAW;
	node->hdr = remain_raw;
	return node;
}

struct proto_node* parse_ipv4_packet(struct raw_pack_stream* rps) {
	const uint8_t* stream = rps_read_ptr(rps);
	struct ipv4_header* ip_header = malloc(sizeof(struct ipv4_header));

	ip_header->ver_ihl = 	stream[0];
	ip_header->dscp_ecn = 	stream[1];
	ip_header->len = 		stream[2] << 8 | 
							stream[3];
	ip_header->id = 		stream[4] << 8 | 
							stream[5];
	ip_header->flags_off = 	stream[6] << 8 | 
							stream[7];
	ip_header->ttl = 		stream[8];
	ip_header->proto = 		stream[9];
	ip_header->chk = 		stream[10] << 8 | 
							stream[11];

	memcpy(ip_header->src, stream + 12, 4);
	memcpy(ip_header->dst, stream + 16, 4);

	one_byte ihl = ip_header->ver_ihl & 0x0F;
	
	struct proto_node* ip_node = create_proto_node();
	ip_node->type = PROTO_IPV4;
	ip_node->hdr = ip_header;

	rps_seek(rps, ihl * 4); // skip ipv4 header

	uint16_t frag_offset = ip_header->flags_off & IP_OFFSET;
	uint8_t frag_df = ip_header->flags_off & IP_MF;
	uint8_t frag_mf = ip_header->flags_off & IP_DF;

	bool is_fragmented = (frag_mf == 1) || (frag_offset > 0);

	// if (is_fragmented) {
	// 	if (frag_mf == 1 && frag_offset == 0) { // first fragment

	// 	}
	// 	else if (frag_mf == 1 && frag_offset > 0) { // middle fragments

	// 	}
	// 	else if(frag_mf == 0 && frag_offset > 0) { // last fragment
	// 		ip_node->next = parse_raw_proto_node(rps);
	// 		return NULL;
	// 	}
	// }
	{
		if (ip_header->proto == IPPROTO_TCP) {
			ip_node->next = parse_tcp_packet(rps);
		}
		else if (ip_header->proto == IPPROTO_UDP) {
			ip_node->next = parse_udp_packet(rps);
		}
		else if (ip_header->proto == IPPROTO_ICMP) {
			ip_node->next = parse_icmp_packet(rps);
		}
	}
	return ip_node;
}
