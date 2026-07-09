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

struct arp_cache_entry arp_table[MAX_CACHE_ENTRIES] = {0};

int arp_table_size = 0;

static void dump_cache_table() {
	puts("\n===== ARP cache table =====");
	fprintf(stdout, "IP\t\tMAC\n");
	for (int i = 0; i < arp_table_size; i++) {
		const struct arp_cache_entry entry = arp_table[i];

		uint32_t ip = entry.ip_addr;
		uint8_t o4 = (ip >> 24) & 0xFF;
		uint8_t o3 = (ip >> 16) & 0xFF;
		uint8_t o2 = (ip >> 8) & 0xFF;
		uint8_t o1 = ip & 0xFF;
		
		uint8_t* mac = entry.mac_addr;

        printf("%d.%d.%d.%d\t\t", o1, o2, o3, o4);
        printf("%02X:%02X:%02X:%02X:%02X:%02X\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	}

	puts("\n");
}

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
			char ip_str[16];
            unsigned char *old = entry->mac_addr;
            const unsigned char *new_mac = hdr->sha;
            
            sprintf(ip_str, "%d.%d.%d.%d", 
                    (sender_ip & 0xFF), ((sender_ip >> 8) & 0xFF), 
                    ((sender_ip >> 16) & 0xFF), ((sender_ip >> 24) & 0xFF));

            printf("[ALERT] ARP Spoofing Detected for IP: %s!\n", ip_str);
            printf("   Cached MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", old[0], old[1], old[2], old[3], old[4], old[5]);
            printf("   Poison MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", new_mac[0], new_mac[1], new_mac[2], new_mac[3], new_mac[4], new_mac[5]);

			dump_cache_table();
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
