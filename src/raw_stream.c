/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2023 Kagati Foundation
 */

#include "raw_stream.h"
#include <stdio.h>

struct raw_pack_stream rps_create(const uint8_t* data, size_t length) {
	struct raw_pack_stream stream = {
		.stream = data,
		.length = length,
		.read_off = 0,
		.payload_len = length
	};

	return stream;
}

void rps_seek(struct raw_pack_stream* rps, size_t n) {
	if (rps == NULL || rps->stream == NULL) return;

	if (n > (rps->length - rps->read_off)) {
		fprintf(
			stderr, 
			"Error: Seek %zu bytes exceeds remaining length %zu\n", 
			n, 
			(rps->length - rps->read_off)
		);
		exit(EXIT_FAILURE);
	}

	rps->payload_len = rps->length - rps->read_off;
	rps->read_off += n;
}

const uint8_t* rps_read_ptr(struct raw_pack_stream* rps) {
	if (rps == NULL || rps->stream == NULL) return NULL;
	if (rps->read_off >= rps->length) return NULL;

	return &rps->stream[rps->read_off];
}

#ifdef TEST_RAW_STREAM_IMPL

#include <string.h>
#include <assert.h>

int main(void) {
	uint8_t* stream = "hello world! what is this place called?";
	struct raw_pack_stream rps = rps_create(stream, strlen(stream));
	rps_seek(&rps, 5);

	assert(rps.read_off == 5);

	uint8_t* rptr = rps_read_ptr(&rps) + 1;
	assert(*rptr == 'w');
	
	printf("%c\n", *rptr);
}

#endif
