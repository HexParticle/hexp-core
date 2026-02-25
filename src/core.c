/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2023 Kagati Foundation
 */

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <ifaddrs.h>

// Check if the interface is Wi-Fi
int is_wireless(const char *ifname);

typedef uint64_t usize;

char **get_all_interfaces_names(usize *count) {
    int capacity = 10;
    int index = 0;

    char **names = malloc(capacity * sizeof(char*));
    if (!names) {
        perror("malloc");
        return NULL;
    }

    struct ifaddrs *addrs;
    if (getifaddrs(&addrs) == -1) {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }

    for (struct ifaddrs *ifa = addrs; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) {
            continue;
        }

        int exists = 0;
        for (int i = 0; i < index; i++) {
            if (strcmp(names[i], ifa->ifa_name) == 0) {
                exists = 1;
                break;
            }
        }
        if (exists) continue;

        if (index >= capacity) {
            capacity *= 2;
            char **temp = realloc(names, capacity * sizeof(char*));
            if (!temp) {
                perror("realloc");
                break;
            }
            names = temp;
        }
        
        names[index] = strdup(ifa->ifa_name);
        if (!names[index]) {
            perror("strdup");
            break;
        }

        index++;
    }

    freeifaddrs(addrs);
    *count = index;
    return names;
}

void free_interfaces_names(char **names, int count) {
    for (int i = 0; i < count; i++) {
        free(names[i]);
    }
    free(names);
}

#ifdef __LINUX__
#include <linus/wireless.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>

// I did not copy this code from Internet. Look how slick it is(unlike MacOS). Sweet Linux.
int is_wireless(const char *ifname) {
    int sock;
    if ((sock = socket(AF_INET, SOCK_DGRAM, 0) < 0)) {
        perror("socket");
        return 0;
    }

    struct iwreq req;
    memset(&req, 0, sizeof req);
    strncpy(req.ifr_name, ifname, IFNAMSIZ);

    int result = ioctl(sock, SIOCGIWNAME, &req);
    close(sock);

    return result != -1;
}
#elif __APPLE__
#include <SystemConfiguration/SystemConfiguration.h>
#include <CoreFoundation/CoreFoundation.h>

// I copied this code from Internet. Look at this mess LMAO. Damn you, MacOS.
int is_wireless(const char *ifname) {
    CFArrayRef interfaces = SCNetworkInterfaceCopyAll();
    for (CFIndex i = 0; i < CFArrayGetCount(interfaces); i++) {
        SCNetworkInterfaceRef iface = (SCNetworkInterfaceRef)CFArrayGetValueAtIndex(interfaces, i);
        CFStringRef bsdName = SCNetworkInterfaceGetBSDName(iface);
        CFStringRef type = SCNetworkInterfaceGetInterfaceType(iface);

        char namebuf[64];
        if (bsdName && CFStringGetCString(bsdName, namebuf, sizeof(namebuf), kCFStringEncodingUTF8)) {
            if (strcmp(namebuf, ifname) == 0) {
                if (CFStringCompare(type, kSCNetworkInterfaceTypeIEEE80211, 0) == kCFCompareEqualTo) {
                    CFRelease(interfaces);
                    return 1; // Wi-Fi
                }
            }
        }
    }
    CFRelease(interfaces);
    return 0;
}
#endif
