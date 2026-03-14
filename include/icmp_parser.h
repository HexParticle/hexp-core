/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2023 Kagati Foundation
 */

#ifndef _ICMPV4_PARSER_H_
#define _ICMPV4_PARSER_H_

#include "icmp.h"
#include "hex.h"
#include "proto_node.h"
#include "raw_stream.h"

HEX_P struct proto_node* parse_icmp_packet(struct raw_pack_stream*);

#endif
