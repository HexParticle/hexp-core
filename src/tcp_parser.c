/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2023 Kagati Foundation
 */

#include "tcp_parser.h"

#include <string.h>

struct proto_node* parse_tcp_packet(struct raw_pack_stream* rps) {
	const uint8_t* stream = rps_read_ptr(rps);
    struct tcp_header* tcp_header = malloc(TCP_HDR_SIZE);
	memcpy(tcp_header, stream, TCP_HDR_SIZE);

	struct proto_node* tcp_node = create_proto_node();
	tcp_node->type = PROTO_TCP;
	tcp_node->hdr = tcp_header;

	rps_seek(rps, TCP_HDR_SIZE);
    return tcp_node;
}
