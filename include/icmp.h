/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2023 Kagati Foundation
 */

#ifndef _HEX_ICMP_H_
#define _HEX_ICMP_H_

#include <stdint.h>

#define ICMP_ECHOREPLY          0 /* echo reply */
#define ICMP_UNREACH            3 /* dest unreachable, codes: */
#define         ICMP_UNREACH_NET        		0               /* bad net */
#define         ICMP_UNREACH_HOST       		1               /* bad host */
#define         ICMP_UNREACH_PROTOCOL   		2               /* bad protocol */
#define         ICMP_UNREACH_PORT       		3               /* bad port */
#define         ICMP_UNREACH_NEEDFRAG   		4               /* IP_DF caused drop */
#define         ICMP_UNREACH_SRCFAIL    		5               /* src route failed */
#define         ICMP_UNREACH_NET_UNKNOWN 		6              	/* unknown net */
#define         ICMP_UNREACH_HOST_UNKNOWN	 	7             	/* unknown host */
#define         ICMP_UNREACH_ISOLATED   		8               /* src host isolated */
#define         ICMP_UNREACH_NET_PROHIB 		9               /* prohibited access */
#define         ICMP_UNREACH_HOST_PROHIB 		10             	/* ditto */
#define         ICMP_UNREACH_TOSNET     		11              /* bad tos for net */
#define         ICMP_UNREACH_TOSHOST    		12              /* bad tos for host */
#define         ICMP_UNREACH_FILTER_PROHIB 		13           	/* admin prohib */
#define         ICMP_UNREACH_HOST_PRECEDENCE 	14         		/* host prec vio. */
#define         ICMP_UNREACH_PRECEDENCE_CUTOFF 	15       		/* prec cutoff */

/**
 * ICMP header version 4.
 */
typedef struct __attribute__((packed)) ICMPHeader {
	uint8_t		type;
	uint8_t		code;
	uint16_t	cksum;
	union {
        struct {
            uint16_t id;
            uint16_t seq;
        } echo;

        uint32_t gateway;

        struct {
            uint16_t unused;
            uint16_t mtu;
        } frag;

        uint32_t raw;
    } rest;
} ICMPHeader_t;

/**
 * ICMP header version 6.
 */
typedef struct __attribute__((packed)) ICMPv6Header {
	uint8_t		type;
	uint8_t		code;
	uint16_t	cksum;
} ICMPv6Header_t;

#endif
