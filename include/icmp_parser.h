/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2023 Kagati Foundation
 */

#ifndef _ICMPV4_PARSER_H_
#define _ICMPV4_PARSER_H_

#include "icmp.h"
#include "hex.h"
#include "proto_node.h"

HEX_P ProtocolNode_t* parse_icmp_packet(const RawPacketStream_t*);

#endif
