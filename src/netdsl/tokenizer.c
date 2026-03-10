/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2023 Kagati Foundation
 */

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "netdsl/token.h"
#include "netdsl/tokenizer.h"

int is_ip_char(char c) {
    return isdigit(c) || c == '.';
}

int is_mac_char(char c) {
    return isxdigit(c) || c == ':';
}

struct token next_token(const char **input) {
    const char *s = *input;

    while (*s && isspace(*s)) s++;

    struct token tok;
    tok.type = TOKEN_UNKNOWN;
    tok.lexeme[0] = '\0';

    if (*s == '\0') {
        tok.type = TOKEN_EOF;
        return tok;
    }

    if (strncmp(s, "from", 4) == 0 && !isalnum(s[4])) {
        tok.type = TOKEN_FROM;
        strcpy(tok.lexeme, "from");
        *input = s + 4;
        return tok;
    }
    if (strncmp(s, "to", 2) == 0 && !isalnum(s[2])) {
        tok.type = TOKEN_TO;
        strcpy(tok.lexeme, "to");
        *input = s + 2;
        return tok;
    }
    if (strncmp(s, "and", 3) == 0 && !isalnum(s[3])) {
        tok.type = TOKEN_AND;
        strcpy(tok.lexeme, "and");
        *input = s + 3;
        return tok;
    }
    if (strncmp(s, "ip", 2) == 0 && !isalnum(s[2])) {
        tok.type = TOKEN_IP;
        strcpy(tok.lexeme, "ip");
        *input = s + 2;
        return tok;
    }
    if (strncmp(s, "port", 4) == 0 && !isalnum(s[4])) {
        tok.type = TOKEN_PORT;
        strcpy(tok.lexeme, "port");
        *input = s + 4;
        return tok;
    }
    if (strncmp(s, "mac", 3) == 0 && !isalnum(s[3])) {
        tok.type = TOKEN_MAC;
        strcpy(tok.lexeme, "mac");
        *input = s + 3;
        return tok;
    }

    if (s[0] == '-' && s[1] == '>') {
        tok.type = TOKEN_ARROW;
        strcpy(tok.lexeme, "->");
        *input = s + 2;
        return tok;
    }

    if (isdigit(*s)) {
        int i = 0;
        while (isdigit(s[i])) tok.lexeme[i] = s[i], i++;
        tok.lexeme[i] = '\0';
        tok.type = TOKEN_NUMBER;
        *input = s + i;
        return tok;
    }

    if (is_ip_char(*s)) {
        int i = 0;
        while (is_ip_char(s[i])) tok.lexeme[i] = s[i], i++;
        tok.lexeme[i] = '\0';
        tok.type = TOKEN_IPADDR;
        *input = s + i;
        return tok;
    }

    if (is_mac_char(*s)) {
        int i = 0;
        while (is_mac_char(s[i])) tok.lexeme[i] = s[i], i++;
        tok.lexeme[i] = '\0';
        tok.type = TOKEN_MACADDR;
        *input = s + i;
        return tok;
    }

    // Unknown character, skip
    tok.lexeme[0] = *s;
    tok.lexeme[1] = '\0';
    tok.type = TOKEN_UNKNOWN;
    (*input)++;
    return tok;
}
