/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2023 Kagati Foundation
 */

#ifndef _ARP_CACHE_H_
#define _ARP_CACHE_H_

#include <stdint.h>

#include "arp_parser.h"

struct arp_cache_entry {
    uint32_t 	ip_addr;
    uint8_t  	mac_addr[6];
    uint64_t 	last_seen;
    int      	is_verified; 
};

void analyze_arp_packet(const struct arp_header* hdr);

#endif
