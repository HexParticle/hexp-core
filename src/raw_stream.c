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
