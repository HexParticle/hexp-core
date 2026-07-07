/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2023 Kagati Foundation
 */

#include <stdint.h>

/**
 * Check if the interface is Wi-Fi.
 * 
 * @returns `1` if the interface is wireless and `0` if it is not.
 * */
int is_wireless(const char *ifname);

char** get_all_interfaces_names(uint64_t *count);

void free_interfaces_names(char **names, int count);
