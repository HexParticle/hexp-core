/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2023 Kagati Foundation
 * 
 * Naive circular queue or ring buffer implementation.
 */

#include "packet_queue.h"

#include <string.h>
#include <stdlib.h>

struct packet_queue* packet_queue_init(void) {
	struct packet_queue* q = calloc(1, sizeof(struct packet_queue));
	
	pthread_mutex_init(&q->__queue_lock, NULL);

	return q;
}

void free_packet_queue(struct packet_queue* q) {
	if (q == NULL) return;

	pthread_mutex_destroy(&q->__queue_lock);
	free(q);
}

bool packet_queue_enqueue(struct packet_queue* q, const struct proto_node* node) {
	if (q == NULL || node == NULL) return false;

	pthread_mutex_lock(&q->__queue_lock);

	if (q->count >= QUEUE_MAX_CAPACITY) {
		pthread_mutex_unlock(&q->__queue_lock);
        return false;
	}

	q->nodes[q->count] = node;

	q->tail = (q->tail + 1) % QUEUE_MAX_CAPACITY;
	q->count += 1;
	
	pthread_mutex_unlock(&q->__queue_lock);
	return true;
}

bool packet_queue_dequeue(struct packet_queue* q, struct proto_node* node) {
	if (q == NULL || node == NULL) return false;

	pthread_mutex_lock(&q->__queue_lock);

	if (q->count >= QUEUE_MAX_CAPACITY) {
		pthread_mutex_unlock(&q->__queue_lock);
        return false;
	}

	memcpy(node, q->nodes[q->head], sizeof(struct proto_node));

	q->head = (q->head + 1) % QUEUE_MAX_CAPACITY;
	q->count -= 1;
	
	pthread_mutex_unlock(&q->__queue_lock);
	return true;
}

uint32_t packet_queue_size(struct packet_queue* q) {
    uint32_t size = 0;

    pthread_mutex_lock(&q->__queue_lock);
 
	size = q->count;
 
	pthread_mutex_unlock(&q->__queue_lock);
	return size;
}