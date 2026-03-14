/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2023 Kagati Foundation
 */

#ifndef _HEXP_UDP_PARSER_H_
#define _HEXP_UDP_PARSER_H_

#include <stdint.h>

#include "hex.h"
#include "proto_node.h"
#include "raw_stream.h"

#define UDP_HEADER_LEN		8 // 8-bytes

struct __attribute__((packed)) udp_header {
	uint16_t	sport;	/* Source port */
	uint16_t	dport;	/* Destination port */
	uint16_t	length; /* Total length */
	uint16_t	cksum;  /* Checksum */
};

HEX_P struct proto_node* parse_udp_packet(struct raw_pack_stream*);

#endif
