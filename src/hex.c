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
#include <unistd.h>
#include <stdatomic.h>

static int __read_next_packet(HexInstnace_t* h) {
    struct pcap_pkthdr *header;
    const uint8_t *stream;

    int res = pcap_next_ex(h->handle, &header, &stream);

	if (res != 1) {
        if (res == 0) {
            h->status = HEX_STATUS_TIMEOUT;
		}
        else if (res == PCAP_ERROR_BREAK) {
            h->status = HEX_STATUS_EOF;
		}
        else if (res == PCAP_ERROR) {
            h->status = HEX_STATUS_ERROR;
		}

        return res;
    }

    struct raw_packet* packet = malloc(sizeof(struct raw_packet));

    packet->length = header->caplen;
    packet->data = malloc(packet->length);

    if (packet->data == NULL) {
        h->status = HEX_STATUS_ERROR;
        return -1;
    }

    memcpy(packet->data, stream, packet->length);

    if (!ring_buffer_enqueue(h->__raw_packs, &packet)) {
        free(packet->data);
        h->status = HEX_STATUS_QUEUE_FULL;
        return -1;
    }

    h->status = HEX_STATUS_OK;
    return 1;
}

// capture thread main
static void* __cthread_main(void* arg) {
	HexInstnace_t* instance = arg;

    while (!atomic_load(&instance->__stop_req)) {
        __read_next_packet(instance);
    }

	return NULL;
}

// processing thread main
static void* __pthread_main(void* arg) {
	HexInstnace_t* instance = arg;

    while (!atomic_load(&instance->__stop_req)) {
		struct raw_packet *raw;

        if (!ring_buffer_dequeue(instance->__raw_packs, (void**) &raw)) {
			continue;
		}

		struct raw_pack_stream stream = rps_create(raw->data, raw->length);

        struct proto_node* node = parse_ether_packet(&stream);

		if (node == NULL) return NULL;

		free(raw->data);
		
		if (!ring_buffer_enqueue(instance->__processed_packs, node)) {
			free_packet(node);
		}
    }

	return NULL;
}

HexInstnace_t* create_hex_instance(const char* source, int mode) {
	char errbuff[PCAP_ERRBUF_SIZE];
	char* dev = strdup(source);

	struct bpf_program program;
	bpf_u_int32 mask;
    bpf_u_int32 net;

	pcap_t* handle = NULL;

	if (mode == HEX_LIVE_MODE) {
		if (pcap_lookupnet(source, &net, &mask, errbuff) == -1) {
        	fprintf(stderr, "Warning: Can't get netmask for device %s: %s\n", source, errbuff);
        	net = 0;
        	mask = 0;
    	}

		handle = pcap_open_live(source, BUFSIZ, 1, 1000, errbuff);
	}
	else if (mode == HEX_OFFLINE_MODE) {
		handle = pcap_open_offline(source, errbuff);
	}
	else {
		fprintf(stderr, "Unknown capture mode '%d'\n", mode);
		goto failure;
	}

    if (!handle) {
        fprintf(stderr, "Couldn't open device %s: %s\n", source, errbuff);
		goto failure;
    }

	HexInstnace_t* instance = malloc(sizeof(HexInstnace_t));
	instance->handle = handle;

	instance->__raw_packs = ring_buffer_init();
	instance->__processed_packs = ring_buffer_init();

	instance->source = dev;
	instance->mask = mask;
	instance->net = net;
	instance->program = program;
	instance->status = HEX_STATUS_OK;

	atomic_init(&instance->__stop_req, false);

	int t_start_res = pthread_create(&instance->__capture_t, NULL, __cthread_main, instance);

	if (t_start_res != 0) {
        fprintf(stderr, "Failed to create capture thread\n");

        free_ring_buffer(instance->__raw_packs);
        free_ring_buffer(instance->__processed_packs);
        pcap_close(instance->handle);
        free(instance->source);
        free(instance);

        return NULL;
    }

	t_start_res = pthread_create(&instance->__processing_t, NULL, __pthread_main, instance);
	
	if (t_start_res != 0) {
        fprintf(stderr, "Failed to create processor thread\n");

        atomic_store(&instance->__stop_req, 1);

        pthread_join(instance->__capture_t, NULL);

        free_ring_buffer(instance->__raw_packs);
        free_ring_buffer(instance->__processed_packs);
  
		pcap_close(instance->handle);

        free(instance->source);
        free(instance);

        return NULL;
    }

	return instance;

failure:
	free(dev);
    exit(EXIT_FAILURE);
}

void free_hex_instance(HexInstnace_t* handle) {
	printf("Deleting HexInstance... ");

	if (handle == NULL || handle->handle == NULL) return;

	atomic_store(&handle->__stop_req, true);

	pthread_join(handle->__capture_t, NULL);
    pthread_join(handle->__processing_t, NULL);

	pcap_close(handle->handle);
	pcap_freecode(&handle->program);

    if (handle->source) free(handle->source);

	if (handle->__raw_packs) free_ring_buffer(handle->__raw_packs);
	if (handle->__processed_packs) free_ring_buffer(handle->__processed_packs);

	free(handle);

	printf("deleted!\n");
}

HEX_P int apply_filter(HexInstnace_t* handle, const char* filter) {
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

struct proto_node* next_packet(HexInstnace_t* h) {
	struct proto_node* node;

	if (!ring_buffer_dequeue(h->__processed_packs, (void**) &node)) {
		return NULL;
	}

	return node;
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
