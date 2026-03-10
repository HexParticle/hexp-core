/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2023 Kagati Foundation
 */

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "netdsl/tokenizer.h"
#include "netdsl/token.h"

int is_network_char(char c) {
    return isalnum(c) || c == '.' || c == ':';
}

struct token next_token(const char **input) {
    const char *s = *input;
    struct token tok = {TOKEN_UNKNOWN, ""};

    while (*s && isspace(*s)) s++;

    if (*s == '\0') {
        tok.type = TOKEN_EOF;
        return tok;
    }

    if (s[0] == '-' && s[1] == '>') {
        tok.type = TOKEN_ARROW;
        strcpy(tok.lexeme, "->");
        *input = s + 2;
        return tok;
    }

    if (is_network_char(*s)) {
        int i = 0;
        int has_dot = 0;
        int has_colon = 0;
        int has_alpha = 0;

        while (is_network_char(s[i]) && i < MAX_LEXEME - 1) {
            if (s[i] == '.') has_dot = 1;
            if (s[i] == ':') has_colon = 1;
            if (isalpha(s[i])) has_alpha = 1;
            tok.lexeme[i] = s[i];
            i++;
        }
        tok.lexeme[i] = '\0';
        *input = s + i;

        if (has_colon) {
            tok.type = TOKEN_MACADDR;
        } else if (has_dot) {
            tok.type = TOKEN_IPADDR;
        } else if (has_alpha) {
            if (strcmp(tok.lexeme, "from") == 0) 		tok.type = TOKEN_FROM;
            else if (strcmp(tok.lexeme, "to") == 0) 	tok.type = TOKEN_TO;
            else if (strcmp(tok.lexeme, "and") == 0) 	tok.type = TOKEN_AND;
            else if (strcmp(tok.lexeme, "ip") == 0) 	tok.type = TOKEN_IP;
            else if (strcmp(tok.lexeme, "port") == 0) 	tok.type = TOKEN_PORT;
            else if (strcmp(tok.lexeme, "mac") == 0) 	tok.type = TOKEN_MAC;
            else tok.type = TOKEN_UNKNOWN;
        } else {
            tok.type = TOKEN_NUMBER;
        }
        return tok;
    }

    tok.lexeme[0] = *s;
    tok.lexeme[1] = '\0';
    tok.type = TOKEN_UNKNOWN;
    *input = s + 1;
    return tok;
}