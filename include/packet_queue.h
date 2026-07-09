/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2023 Kagati Foundation
 */

#ifndef _PACKET_QUEUE_H_
#define _PACKET_QUEUE_H_

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>

#include "proto_node.h"

#define QUEUE_MAX_CAPACITY 4096

struct packet_queue {
    struct proto_node const* 	nodes[QUEUE_MAX_CAPACITY];
    uint32_t 					count; /** Number of items in the queue */
	uint32_t					head;
	uint32_t 					tail;
	pthread_mutex_t				__queue_lock;
};

struct packet_queue* packet_queue_init(void);

bool packet_queue_enqueue(struct packet_queue* q, const struct proto_node* node);

bool packet_queue_dequeue(struct packet_queue* q, struct proto_node* node);

uint32_t packet_queue_size(struct packet_queue* q);

#endif // _PACKET_QUEUE_H_