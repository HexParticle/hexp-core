/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2023 Kagati Foundation
 */

#include "udp_parser.h"

#include <string.h>
#include <stdlib.h>

struct proto_node* parse_udp_packet(struct raw_pack_stream* rps) {
	const uint8_t* stream = rps_read_ptr(rps);
	struct udp_header* udp_hdr = malloc(UDP_HEADER_LEN);
	memcpy(udp_hdr, stream, UDP_HEADER_LEN);

	struct proto_node* udp_node = create_proto_node();
	udp_node->hdr = udp_hdr;
	udp_node->type = PROTO_UDP;
	udp_node->hdr_len = UDP_HEADER_LEN;
	
	rps_seek(rps, UDP_HEADER_LEN);
	return udp_node;
}