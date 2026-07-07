/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2023 Kagati Foundation
 */

#ifndef _HEX_PARTICLE_ANALYZER_H_
#define _HEX_PARTICLE_ANALYZER_H_

#include <pcap.h>
#include "proto_node.h"

/* Macro for symbol visibility, currently empty */
#define HEX_P

#define HEX_OUT_BUF_SIZE 4096

#define HEX_LIVE_MODE		0x1
#define HEX_OFFLINE_MODE	0x2

typedef enum hex_status {
    HEX_STATUS_OK = 0,         // Packet read successfully
    HEX_STATUS_TIMEOUT,        // Live capture timeout
    HEX_STATUS_EOF,            // Offline file reached End-Of-File 
    HEX_STATUS_ERROR           // Interface error or packet read failure 
} hex_status_t;

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
	enum hex_status			status;
} HexInstnace_t;

/**
 * @brief Creates and initializes a new HexInstance for packet processing.
 *
 * Configures the underlying libpcap engine for either live interface capture
 * or offline pcap/pcapng file analysis based on the operational mode.
 *
 * @param source The packet stream source. This must be a valid network interface 
 * name (e.g., "eth0", "wlan0") if mode is live, or a valid filesystem 
 * path to a capture file if mode is offline.
 * @param mode   The operational mode selection. Must be either:
 * - @c HEX_LIVE_MODE : Stream live packets from a local hardware interface.
 * - @c HEX_OFFLINE_MODE : Parse an existing trace file.
 *
 * @return A HexInstnace structure containing the active pcap handle.
 * @note This function will terminate the process if the source cannot be processed.
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
HEX_P struct proto_node* read_next_packet(HexInstnace_t* handle);

HEX_P int apply_filter(HexInstnace_t* handle, const char* filter);

HEX_P void free_packet(struct proto_node* node);

#endif
