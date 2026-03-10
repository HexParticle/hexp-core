/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2023 Kagati Foundation
 */

#ifndef _HEXP_PARSER_H_
#define _HEXP_PARSER_H_

#include <stdlib.h>

#include "ast.h"
#include "token.h"
#include "netdsl/ast.h"
#include "netdsl/tokenizer.h"

struct parser_ctx {
    struct token *tokens;
    int current;
	int total;
};

struct stmt* parse_from_stmt(struct parser_ctx *ctx);
struct expr* parse_expr(struct parser_ctx *ctx);

// TODO: implement the following functions
// void free_from_stmt(struct from_stmt* s);

// void free_ip_expr(struct ip_expr* e);

// void free_port_expr(struct port_expr* e);

#endif
