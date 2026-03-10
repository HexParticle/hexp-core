/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2023 Kagati Foundation
 */

#ifndef _HEXP_AST_H_
#define _HEXP_AST_H_

#include <stdint.h>

enum bin_expr_type {
	BEXPR_AND
};

enum expr_type {
	EXPR_BIN,
	EXPR_LIT,
	EXPR_IP,
	EXPR_PORT
};

enum stmt_type {
	STMT_FROM
};

struct ip_addr {
	uint8_t octets[4];
};

struct ip_expr {
	struct ip_addr value;
};

struct port_expr {
	uint16_t value;
};

struct expr {
	enum expr_type type;
	void* e;
};

struct lit_expr {
	int value;
};

struct bin_expr {
	struct expr* lhs;
	struct expr* rhs;
	enum bin_expr_type type;
};

struct stmt {
	enum stmt_type type;
	void* s;
};

struct from_stmt {
	struct expr* from;
	struct expr* to;
};

#endif
