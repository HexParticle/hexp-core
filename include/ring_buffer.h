/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2023 Kagati Foundation
 * 
 * Naive circular queue or ring buffer implementation.
 */

#ifndef _RING_BUFFER_H_
#define _RING_BUFFER_H_

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>

#define RING_BUFFER_CAPACITY 4096

struct ring_buffer {
    void* items[RING_BUFFER_CAPACITY];

    uint32_t count;
    uint32_t head;
    uint32_t tail;

    pthread_mutex_t __lock;
};

struct ring_buffer* ring_buffer_init(void);

void free_ring_buffer(struct ring_buffer* buffer);

bool ring_buffer_enqueue(struct ring_buffer* buffer, void* item);

bool ring_buffer_dequeue(struct ring_buffer* buffer, void** item);

uint32_t ring_buffer_size(struct ring_buffer* buffer);

#endif
