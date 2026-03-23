/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2023 Kagati Foundation
 */

#ifndef TCP_PARSER_H
#define TCP_PARSER_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "hex.h"
#include "proto_node.h"
#include "raw_stream.h"

struct __attribute__((packed)) tcp_option {
	uint8_t	kind;
	uint8_t length;
	uint8_t data[];
};

/**
 * TCP header
 */
struct __attribute__((packed)) tcp_header {
    uint16_t    sport;
    uint16_t    dport;
    uint32_t    seq;
    uint32_t    ack;
    uint8_t     off_res;
    uint8_t     flags;
    uint16_t    win;
    uint16_t    chk;
    uint16_t    urg;
    struct tcp_option  options[];
};

HEX_P struct proto_node* parse_tcp_packet(struct raw_pack_stream*);

#define TCP_HDR_SIZE sizeof(struct tcp_header)

#endif
