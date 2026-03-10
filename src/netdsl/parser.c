/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2023 Kagati Foundation
 */

#include "netdsl/parser.h"
#include "ip.h"

#include <stdio.h>
#include <stdlib.h>

struct token peek(struct parser_ctx *ctx) { 
	if (ctx->current >= ctx->total) {
		return (struct token) { .lexeme = "", .type = TOKEN_EOF };
	}
	return ctx->tokens[ctx->current]; 
}

struct token consume(struct parser_ctx *ctx) {
    if (ctx->current >= ctx->total) {
        return (struct token){ .type = TOKEN_EOF, .lexeme = "" };
    }
    return ctx->tokens[ctx->current++];
}

struct token consume_type(struct parser_ctx* ctx, enum token_type type) {
	if (ctx->current >= ctx->total) {
        return (struct token){ .type = TOKEN_EOF, .lexeme = "" };
    }

	struct token tok = ctx->tokens[ctx->current++];
	if (tok.type != type) {
		fprintf(stderr, "Tokens don't match");
		exit(EXIT_FAILURE);
	}

	return tok;
}

struct stmt* parse_from_stmt(struct parser_ctx *ctx) {
    consume(ctx);
    
    struct from_stmt* from_s = calloc(sizeof(struct from_stmt), 1);
    from_s->from = parse_expr(ctx);
    
    if (peek(ctx).type == TOKEN_TO) consume(ctx);
    
    from_s->to = parse_expr(ctx);
    
    struct stmt* s = calloc(sizeof(struct stmt), 1);
    s->type = STMT_FROM;
    s->s = from_s;
    
    return s;
}

/**
 * 
 * Expression parsers
 * 
 */

struct ip_expr* parse_ip_expr(struct parser_ctx* ctx);
struct port_expr* parse_port_expr(struct parser_ctx* ctx);

struct ip_addr ip_addr_from_str(const char* str) {
    struct ip_addr addr;
    unsigned int o1, o2, o3, o4;

    if (sscanf(str, "%u.%u.%u.%u", &o1, &o2, &o3, &o4) == IPV4_ADDR_LEN) {
        addr.octets[0] = (uint8_t)o1;
        addr.octets[1] = (uint8_t)o2;
        addr.octets[2] = (uint8_t)o3;
        addr.octets[3] = (uint8_t)o4;
    } else {
        fprintf(stderr, "Invalid IP address");
		exit(EXIT_FAILURE);
    }

    return addr;
}

struct expr* parse_expr(struct parser_ctx *ctx) {
    struct token t = peek(ctx);
	if (t.type == TOKEN_EOF) return NULL;

    struct expr* e = malloc(sizeof(struct expr));
	if (!e) return NULL;

    if (t.type == TOKEN_NUMBER) {
        consume(ctx);
        struct lit_expr* lit = calloc(sizeof(struct lit_expr), 1);
        lit->value = atoi(t.lexeme);
        e->type = EXPR_LIT;
        e->e = lit;
    }
	else if (t.type == TOKEN_IP) {
		struct ip_expr* ip_e = parse_ip_expr(ctx);
		e->e = ip_e;
		e->type = EXPR_IP;
	}
	else if (t.type == TOKEN_PORT) {
		struct port_expr* port_e = parse_port_expr(ctx);
		e->e = port_e;
		e->type = EXPR_PORT;
	}
	else {
        free(e);
        return NULL;
    }
    return e;
}

struct ip_expr* parse_ip_expr(struct parser_ctx* ctx) {
	consume_type(ctx, TOKEN_IP);

	struct ip_expr* e = calloc(sizeof(struct ip_expr), 1);
	if (e == NULL) {
		fprintf(stderr, "Failed to malloc");
		return NULL;
	}

	struct token ip = consume_type(ctx, TOKEN_IPADDR);
	struct ip_addr addr = ip_addr_from_str(ip.lexeme);

	e->value = addr;
	return e;
}

struct port_expr* parse_port_expr(struct parser_ctx* ctx) {
	struct port_expr* e = malloc(sizeof(struct port_expr));
	if (e == NULL) {
		fprintf(stderr, "Failed to malloc");
		return NULL;
	}

	e->value = 3333;
	return e;
}
