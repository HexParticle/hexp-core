/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2023 Kagati Foundation
 */

#include "arp_cache.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define MAX_CACHE_ENTRIES 1024

#define ARP_HEADER_PA(arp_hdr_ptr, field) \
	((uint32_t)(arp_hdr_ptr)->field[3] << 24) | \
	((uint32_t)(arp_hdr_ptr)->field[2] << 16) | \
	((uint32_t)(arp_hdr_ptr)->field[1] << 8)  | \
	((uint32_t)(arp_hdr_ptr)->field[0])

/**
 * ARP cache table.
*/
struct arp_cache_entry arp_table[MAX_CACHE_ENTRIES] = {0};

/**
 * The callback to be called for each spoofed ARP packet.
 */
static arp_alert_callback g_alert_callback = NULL;

/**
 * Size of the ARP cache table.
 */
int arp_table_size = 0;

struct arp_cache_entry* find_arp_entry(uint32_t ip) {
    for (int i = 0; i < arp_table_size; i++) {
        if (arp_table[i].ip_addr == ip) {
            return &arp_table[i];
        }
    }
    return NULL;
}

void analyze_arp_packet(const struct arp_header* hdr) {
	if (hdr == NULL) return;

	uint32_t sender_ip = ARP_HEADER_PA(hdr, spa);
	uint8_t* sender_mac = hdr->sha;

	struct arp_cache_entry* entry = find_arp_entry(sender_ip);

	if (entry != NULL) {
		if (memcmp(entry->mac_addr, hdr->sha, 6) != 0) {
            unsigned char *old = entry->mac_addr;
            const unsigned char *new_mac = hdr->sha;

			char ip_str[16];
					 
            sprintf(
				ip_str, 
				"%d.%d.%d.%d", 
                (sender_ip & 0xFF), ((sender_ip >> 8) & 0xFF), 
                ((sender_ip >> 16) & 0xFF), ((sender_ip >> 24) & 0xFF)
			);

			struct arp_alert alert;
			alert.ip_address = sender_ip;
			memcpy(alert.cached_mac, entry->mac_addr, 6);
			memcpy(alert.poison_mac, sender_mac, 6);
			
			g_alert_callback(&alert);
		}
	}
	else {
        if (arp_table_size < MAX_CACHE_ENTRIES) {
            arp_table[arp_table_size].ip_addr = sender_ip;
            memcpy(arp_table[arp_table_size].mac_addr, sender_mac, 6);
            arp_table[arp_table_size].last_seen = 12345678;
            arp_table_size++;
        }
    }
}

void register_arp_alert_callback(arp_alert_callback cb) {
	g_alert_callback = cb;
}

const struct arp_cache_entry* get_arp_table(int* out_size) {
    if (out_size) *out_size = arp_table_size;
    return arp_table;
}
