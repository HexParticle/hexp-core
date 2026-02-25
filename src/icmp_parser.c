/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2023 Kagati Foundation
 */

#include "icmp_parser.h"
#include <stdlib.h>

ProtocolNode_t* parse_icmp_packet(const RawPacketStream_t* stream) {
	const uint8_t* raw = stream->stream;

	ICMPHeader_t* icmp_hdr = malloc(sizeof(ICMPHeader_t));
	icmp_hdr->type 		= raw[0];
	icmp_hdr->code 		= raw[1];
	icmp_hdr->cksum 	= ((uint16_t) raw[2] << 8) | (uint8_t) raw[3];
	icmp_hdr->rest		= 
		((uint32_t) raw[4] << 24) | 
		((uint32_t) raw[5] << 16) | 
		((uint32_t) raw[6] << 8) | 
		((uint32_t) raw[7]);

	ProtocolNode_t* icmp_node = create_proto_node();
	icmp_node->type = PROTO_ICMP;
	icmp_node->hdr  = icmp_hdr;

	return icmp_node;
}