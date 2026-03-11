/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2023 Kagati Foundation
 */

#ifndef _HEXP_BPF_GEN_H_
#define _HEXP_BPF_GEN_H_

#include "ast.h"
#include "sds/sds.h"

#include <stdlib.h>

#define BPF_SUCCESS 	1
#define BPF_ERROR		-1

int bpf_gen_stmt(struct stmt* s, char** sb);

#endif
