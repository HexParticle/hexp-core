/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2023 Kagati Foundation
 */

#include "tcp_parser.h"

#include <string.h>
#include <arpa/inet.h>

struct proto_node* parse_tcp_packet(struct raw_pack_stream* rps) {
	const uint8_t* stream = rps_read_ptr(rps);
	size_t hdr_size = (stream[12] >> 4) * 4;

	if (hdr_size < 20) {
        fprintf(stderr, "Malformed packet: TCP header size too small (%zu bytes)\n", hdr_size);
        return NULL; 
    }

    struct tcp_header* tcp_header = malloc(hdr_size);
	if (tcp_header == NULL) {
		fprintf(stderr, "malloc failed");
		return NULL;
	}

	memcpy(tcp_header, stream, hdr_size);

	tcp_header->sport 	= ntohs(tcp_header->sport);
    tcp_header->dport 	= ntohs(tcp_header->dport);
    tcp_header->seq  	= ntohl(tcp_header->seq);
    tcp_header->ack  	= ntohl(tcp_header->ack);
    tcp_header->win 	= ntohs(tcp_header->win);
    tcp_header->chk 	= ntohs(tcp_header->chk);
    tcp_header->urg  	= ntohs(tcp_header->urg);

	struct proto_node* tcp_node = create_proto_node();
	tcp_node->type = PROTO_TCP;
	tcp_node->hdr = tcp_header;

	rps_seek(rps, hdr_size);
    return tcp_node;
}
