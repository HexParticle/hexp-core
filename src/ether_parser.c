/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2023 Kagati Foundation
 */

#include "proto_node.h"
#include "ether_parser.h"
#include "ipv4_parser.h"
#include "arp_parser.h"
#include "ipv6_parser.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static int parse_vlan_tags(struct ether_header* eth_header, struct raw_pack_stream*);

struct proto_node* parse_ether_packet(struct raw_pack_stream* stream) {
	const uint8_t* raw = stream->stream;
	size_t eth_hdr_size = ETH_HDR_SIZE;
	struct ether_header* eth_header = malloc(eth_hdr_size);

	if (eth_header == NULL) {
		fprintf(stderr, "Failed to allocate memory for Ethernet header\n");
		return NULL;
	}

    memcpy(eth_header->dst_mac, raw, MAC_ADDR_LEN);
    memcpy(eth_header->src_mac, raw + 6, MAC_ADDR_LEN);
	eth_header->type = (raw[12] << 8) | raw[13];

	rps_seek(stream, eth_hdr_size); // skip ether header
	int payload_off = parse_vlan_tags(eth_header, stream);

	if (payload_off < 0) {
		free(eth_header);
		fflush(stderr);
		return NULL;
	}

	struct proto_node* ether_node = create_proto_node();
	ether_node->type = PROTO_ETH;
	ether_node->hdr = eth_header;
    
    if (eth_header->type <= 1500) {
        fprintf(stderr, "Skipping IEEE 802.3 frame (unsupported).\n");
		fflush(stderr);
		free(eth_header);
		free(ether_node);
        return NULL;
    }

	if (eth_header->type == ETHER_TYPE_IPV4) {
		ether_node->next = parse_ipv4_packet(stream);
	}
	else if (eth_header->type == ETHER_TYPE_ARP) {
		ether_node->next = parse_arp_packet(stream);
	}
	else if (eth_header->type == ETHER_TYPE_IPV6) {
		ether_node->next = parse_ipv6_packet(stream);
	}

	return ether_node;
}

static int parse_vlan_tags(struct ether_header* eth_header, struct raw_pack_stream* rps) {
	int payload_off = ETHER_PAYLOAD_OFF;
	const uint8_t* stream = rps_read_ptr(rps);
	size_t len = rps->length;

	eth_header->vlan_count = 0;

	while (eth_header->type == ETHER_TYPE_VLAN) {
		if (eth_header->vlan_count >= MAX_VLAN_STACK) {
			fprintf(stderr, "Warning: VLAN stack overflow.\n");
			return -1;
		};

        if (len < payload_off + 4) {
            fprintf(stderr, "Malformed packet.\n");
            return -1;
        }

		struct vlan_tag tag = {
			.tpid = ETHER_TYPE_VLAN,
			.tci = (stream[payload_off] << 8) | (stream[payload_off + 1])
		};

		eth_header->vlans[eth_header->vlan_count] = tag;
        eth_header->type = 
			((uint16_t) stream[payload_off + 2] << 8) | 
			((uint16_t) stream[payload_off + 3]);

        payload_off += 4;
		eth_header->vlan_count += 1;
    }

	if (eth_header->vlan_count > 0) {
		rps_seek(rps, eth_header->vlan_count * 4); // skip each vlan tag
	}

	return payload_off;
}
