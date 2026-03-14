/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2023 Kagati Foundation
 */

#include "hex.h"
#include "ipv4_parser.h"
#include "ether_parser.h"
#include "raw_stream.h"

#include <stdlib.h>
#include <string.h>

HexInstnace_t create_hex_instance(const char* device) {
	char errbuff[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuff);
    if (!handle) {
        fprintf(stderr, "Couldn't open device %s: %s\n", device, errbuff);
        exit(EXIT_FAILURE);
    }

	return (HexInstnace_t) { .handle = handle };
}

void free_hex_instance(HexInstnace_t* handle) {
	if (handle == NULL || handle->handle == NULL) return;

	pcap_close(handle->handle);
	handle->handle = NULL;
}

struct proto_node* read_next_packet(const HexInstnace_t* instance) {
	struct pcap_pkthdr *header;
	const char* stream;
	int res = pcap_next_ex(instance->handle, &header, &stream);

	struct raw_pack_stream raw_stream = { .stream = stream, .length = header->caplen };
	
	if (res == 1) {
		struct proto_node* node = parse_ether_packet(&raw_stream);
		return node;
	}

	return NULL;
}

void free_packet(struct proto_node* head) {
	struct proto_node* current = head;

    while (current != NULL) {
        struct proto_node* next_node = current->next;
        if (current->hdr != NULL) { 
			free(current->hdr);
		}

        free(current);
        current = next_node;
    }
}
