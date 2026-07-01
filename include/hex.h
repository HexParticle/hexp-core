/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2023 Kagati Foundation
 */

#include <pcap.h>
#include "proto_node.h"

/* Macro for symbol visibility, currently empty */
#define HEX_P

#define HEX_OUT_BUF_SIZE 4096

#ifndef HEX_PARTICLE_ANALYZER_H
#define HEX_PARTICLE_ANALYZER_H

#define HEX_LIVE_MODE		0x1
#define HEX_OFFLINE_MODE	0x2

/**
 * @struct HexInstance_t
 * @brief Container for the libpcap session handle.
 */
typedef struct _HexInstnace {
    pcap_t* 				handle;	/* libpcap session handle */
	char* 					source;
	struct bpf_program		program;
	bpf_u_int32 			mask;
	bpf_u_int32 			net;
} HexInstnace_t;

/**
 * @brief Initializes a live capture session on the specified network device.
 * @param device The name of the interface (e.g., "eth0").
 * @return A HexInstnace_t structure containing the active pcap handle.
 * @note This function will terminate the process if the device cannot be opened.
 */
HEX_P HexInstnace_t* create_hex_instance(const char* source, int mode);

/**
 * @brief Closes the pcap handle and releases associated instance memory.
 * @param handle Pointer to the instance to be destroyed.
 */
HEX_P void free_hex_instance(HexInstnace_t* handle);

/**
 * @brief Captures the next packet and parses it into a protocol chain.
 * @param handle Pointer to the active sniffer instance.
 * @return proto_node* The head of the parsed linked list.
 * @warning Returns heap-allocated memory. Caller must use free_protocol_node() 
 * to prevent memory leaks.
 */
HEX_P struct proto_node* read_next_packet(const HexInstnace_t* handle);

HEX_P int apply_filter(HexInstnace_t* handle, const char* filter);

HEX_P void free_packet(struct proto_node* node);

#endif
