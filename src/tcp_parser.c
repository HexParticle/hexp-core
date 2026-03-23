/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2023 Kagati Foundation
 */

#include "tcp_parser.h"

#include <string.h>

struct proto_node* parse_tcp_packet(struct raw_pack_stream* rps) {
	const uint8_t* stream = rps_read_ptr(rps);
	size_t hdr_size = (stream[12] >> 4) * 4;

	if (hdr_size < 20) hdr_size = 20;

    struct tcp_header* tcp_header = malloc(hdr_size);
	if (tcp_header == NULL) {
		fprintf(stderr, "malloc failed");
		return NULL;
	}

	memcpy(tcp_header, stream, hdr_size);

	struct proto_node* tcp_node = create_proto_node();
	tcp_node->type = PROTO_TCP;
	tcp_node->hdr = tcp_header;

	rps_seek(rps, hdr_size);
    return tcp_node;
}
