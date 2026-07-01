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

HexInstnace_t create_hex_instance(const char* source, int mode) {
	char* errbuff = malloc(PCAP_ERRBUF_SIZE);
	char* dev = strdup(source);

	struct bpf_program program;
	bpf_u_int32 mask;
    bpf_u_int32 net;

	if (pcap_lookupnet(source, &net, &mask, errbuff) == -1) {
        fprintf(stderr, "Warning: Can't get netmask for device %s: %s\n", source, errbuff);
        net = 0;
        mask = 0;
    }

	pcap_t* handle = NULL;

	if (mode == HEX_LIVE_MODE) {
		handle = pcap_open_live(source, BUFSIZ, 1, 1000, errbuff);
	}
	else if (mode == HEX_OFFLINE_MODE) {
		handle = pcap_open_offline(source, errbuff);
	}
	else {
		fprintf(stderr, "Unknown capture mode '%d'\n", mode);
		exit(1);
	}

    if (!handle) {
        fprintf(stderr, "Couldn't open device %s: %s\n", source, errbuff);
        exit(EXIT_FAILURE);
    }

	return (HexInstnace_t) { 
		.handle = handle, 
		.errbuff = errbuff, 
		.source = source,
		.mask = mask,
		.net = net,
		.program = program
	};
}

void free_hex_instance(HexInstnace_t* handle) {
	if (handle == NULL || handle->handle == NULL) return;

	pcap_close(handle->handle);
	pcap_freecode(&handle->program);

	if (handle->errbuff) free(handle->errbuff);
    if (handle->source) free(handle->source);

	handle->handle = NULL;
}

struct proto_node* read_next_packet(const HexInstnace_t* instance) {
	struct pcap_pkthdr *header;
	const uint8_t* stream;
	int res = pcap_next_ex(instance->handle, &header, &stream);

	struct raw_pack_stream raw_stream = { .stream = stream, .length = header->caplen };
	
	if (res == 1) {
		struct proto_node* node = parse_ether_packet(&raw_stream);
        node->length = header->caplen;
		return node;
	}

	return NULL;
}

HEX_P int apply_filter(const HexInstnace_t* handle, const char* filter) {
	pcap_freecode(&handle->program); // freeing previously compiled bytecode

	if (pcap_compile(handle->handle, &handle->program, filter, 0, handle->net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter, pcap_geterr(handle->handle));
        return -1;
    }

	if (pcap_setfilter(handle->handle, &handle->program) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter, pcap_geterr(handle->handle));
        pcap_freecode(&handle->program);
        return -1;
    }
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
