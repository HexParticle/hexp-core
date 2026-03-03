/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2023 Kagati Foundation
 */

#include "raw_stream.h"

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

	rps->payload_len = rps->length - n;
	rps->read_off += n;
}

const uint8_t* rps_read_ptr(struct raw_pack_stream* rps) {
	if (rps == NULL) return NULL;
	return rps->stream + rps->read_off;
}
