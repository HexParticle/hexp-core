/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2023 Kagati Foundation
 */

#ifndef _HEXP_RAW_PACK_STREAM_H_
#define _HEXP_RAW_PACK_STREAM_H_

#include <stdint.h>
#include <stdlib.h>

struct raw_pack_stream {
	const uint8_t* 	stream;
	size_t			length;
	size_t			payload_len;
	size_t			read_off; /* Offset to read the stream from. */
};

struct raw_pack_stream rps_create(const uint8_t* data, size_t length);

void rps_seek(struct raw_pack_stream*, size_t);

const uint8_t* rps_read_ptr(struct raw_pack_stream*);

#endif
