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
};

struct stmt* parse_from_stmt(struct parser_ctx *ctx);
struct expr* parse_expr(struct parser_ctx *ctx);

#endif
