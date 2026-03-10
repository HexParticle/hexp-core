/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2023 Kagati Foundation
 */

#include "netdsl/parser.h"

#include <stdio.h>
#include <stdlib.h>

struct token peek(struct parser_ctx *ctx) { 
	return ctx->tokens[ctx->current]; 
}

struct token consume(struct parser_ctx *ctx) {
	return ctx->tokens[ctx->current++];
}

struct stmt* parse_from_stmt(struct parser_ctx *ctx) {
    consume(ctx);
    
    struct from_stmt* from_s = malloc(sizeof(struct from_stmt));
    from_s->from = parse_expr(ctx);
    
    if (peek(ctx).type == TOKEN_TO) consume(ctx);
    
    from_s->to = parse_expr(ctx);
    
    struct stmt* s = malloc(sizeof(struct stmt));
    s->type = FROM;
    s->s = from_s;
    
    return s;
}

struct expr* parse_expr(struct parser_ctx *ctx) {
    struct token t = peek(ctx);
    struct expr* e = malloc(sizeof(struct expr));

    if (t.type == TOKEN_NUMBER) {
        consume(ctx);
        struct lit_expr* lit = malloc(sizeof(struct lit_expr));
        lit->value = atoi(t.lexeme);
        e->type = LIT;
        e->e = lit;
    }
    return e;
}