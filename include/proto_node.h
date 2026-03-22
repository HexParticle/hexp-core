/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2023 Kagati Foundation
 */

#ifndef _HEXP_PROTO_NODE_H_
#define _HEXP_PROTO_NODE_H_

#include <stdint.h>

enum proto_type {
    PROTO_ETH,
    PROTO_IPV4,
    PROTO_IPV6,
    PROTO_ARP,
    PROTO_TCP,
    PROTO_UDP,
	PROTO_ICMP,
	PROTO_IPV6_EXT,
	PROTO_IPV6_EXT_HOP_BY_HOP,
	PROTO_IPV6_EXT_DST_OPTS,
	PROTO_IPV6_EXT_FRAG,
	PROTO_ICMPV6,
    PROTO_RAW
};

#define one_byte 	uint8_t
#define two_bytes 	uint16_t
#define four_bytes 	uint32_t
#define eight_bytes uint64_t

struct proto_node {
    enum proto_type 		type;
    void* 					hdr;
    uint32_t				hdr_len;
    uint32_t				length;
    struct proto_node* 		next;
};

struct proto_node* create_proto_node(void);

#endif
