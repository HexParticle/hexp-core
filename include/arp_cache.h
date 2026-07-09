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

struct arp_alert {
    uint32_t 	ip_address;
    uint8_t 	cached_mac[6]; 
    uint8_t 	poison_mac[6];
};

void analyze_arp_packet(const struct arp_header* hdr);

typedef void (*arp_alert_callback) (const struct arp_alert *alert);

void register_arp_alert_callback(arp_alert_callback cb);

const struct arp_cache_entry* get_arp_table(int* out_size);

#endif
