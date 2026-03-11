/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2023 Kagati Foundation
 */

#include "netdsl/bpf_gen.h"

int bpf_dump_ip_expr(struct ip_expr* e, const char* direction, char** sb) {
	*sb = sdscatprintf(
		*sb, 
		"%s host %u.%u.%u.%u",
		direction,
        (unsigned int)e->value.octets[0],
        (unsigned int)e->value.octets[1],
        (unsigned int)e->value.octets[2],
        (unsigned int)e->value.octets[3]
	);
	return BPF_SUCCESS;
}

int bpf_dump_expr(struct expr* e, const char* direction, char** sb) {
    if (e->type == EXPR_IP) {
        return bpf_dump_ip_expr((struct ip_expr*)e->e, direction, sb);
    }

	return BPF_ERROR;
}

int bpf_gen_from_stmt(struct from_stmt* fs, char** sb) {
    if (fs->from) {
        int res = bpf_dump_expr(fs->from, "src", sb);
		if (res < 0) return BPF_ERROR;
    }
    if (fs->from && fs->to) {
        *sb = sdscat(*sb, " and ");
    }
    if (fs->to) {
        int res = bpf_dump_expr(fs->to, "dst", sb);
		if (res < 0) return BPF_ERROR;
    }

	return 1;
}

int bpf_gen_stmt(struct stmt* s, char** sb) {
	if (s == NULL || sb == NULL) return BPF_ERROR;

	if (s->type == STMT_FROM) {
        struct from_stmt* fs = (struct from_stmt*) s->s;

		return bpf_gen_from_stmt(fs, sb);
    }

	return BPF_ERROR;
}