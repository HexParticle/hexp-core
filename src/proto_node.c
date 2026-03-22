/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2023 Kagati Foundation
 */

#include <stdlib.h>
#include <stdio.h>

#include "proto_node.h"

struct proto_node* create_proto_node(void) {
	struct proto_node* node = malloc(sizeof(struct proto_node));
	if (node) {
		node->hdr 	= NULL;
		node->next 	= NULL;
		node->type 	= -1;
        node->length = 0;
	}
	else {
		fprintf(stderr, "malloc failed when creating a protocol node");
		exit(EXIT_FAILURE);
	}
	return node;
}
