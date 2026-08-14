/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2023 Kagati Foundation
 *
 * Naive circular ring buffer implementation.
 */

#include "ring_buffer.h"

#include <stdlib.h>

struct ring_buffer* ring_buffer_init(void) {
    struct ring_buffer* buffer = calloc(1, sizeof(struct ring_buffer));

    if (buffer == NULL) {
        return NULL;
	}

    pthread_mutex_init(&buffer->__lock, NULL);

    return buffer;
}

void free_ring_buffer(struct ring_buffer* buffer) {
    if (buffer == NULL) {
        return;
	}

    pthread_mutex_destroy(&buffer->__lock);
    free(buffer);
}

bool ring_buffer_enqueue(struct ring_buffer* buffer, void* item) {
    if (buffer == NULL || item == NULL) {
        return false;
	}

    pthread_mutex_lock(&buffer->__lock);

    if (buffer->count >= RING_BUFFER_CAPACITY) {
        pthread_mutex_unlock(&buffer->__lock);
        return false;
    }

    buffer->items[buffer->tail] = item;

    buffer->tail = (buffer->tail + 1) % RING_BUFFER_CAPACITY;

    buffer->count++;

    pthread_mutex_unlock(&buffer->__lock);

    return true;
}

bool ring_buffer_dequeue(struct ring_buffer* buffer, void** item) {
    if (buffer == NULL || item == NULL) {
        return false;
	}

    pthread_mutex_lock(&buffer->__lock);

    if (buffer->count == 0) {
        pthread_mutex_unlock(&buffer->__lock);
        return false;
    }

    *item = buffer->items[buffer->head];

    buffer->head = (buffer->head + 1) % RING_BUFFER_CAPACITY;

    buffer->count--;

    pthread_mutex_unlock(&buffer->__lock);

    return true;
}

uint32_t ring_buffer_size(struct ring_buffer* buffer) {
    if (buffer == NULL) {
        return 0;
	}

    pthread_mutex_lock(&buffer->__lock);

    uint32_t size = buffer->count;

    pthread_mutex_unlock(&buffer->__lock);

    return size;
}
