/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2023 Kagati Foundation
 */

#ifndef HEXP_TOKEN_H
#define HEXP_TOKEN_H

#define MAX_LEXEME 64

typedef enum token_type {
    TOKEN_FROM,
    TOKEN_TO,
    TOKEN_AND,
    TOKEN_OR,
    TOKEN_NOT,
    TOKEN_IP,
    TOKEN_PORT,
    TOKEN_MAC,
    TOKEN_NUMBER,
    TOKEN_IPADDR,
    TOKEN_MACADDR,
    TOKEN_ARROW,
    TOKEN_EOF,
    TOKEN_UNKNOWN
} token_type_t;

typedef struct token {
    enum token_type 	type;
    char 				lexeme[64];
} token_t;

#endif
