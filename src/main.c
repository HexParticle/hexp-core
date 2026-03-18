/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2023 Kagati Foundation
 */

#include "hex.h"
#include "ether_parser.h"
#include "ipv4_parser.h"
#include "ipv6_parser.h"
#include "tcp_parser.h"
#include "udp_parser.h"
#include "arp_parser.h"
#include "icmp.h"
#include "netdsl/tokenizer.h"
#include "netdsl/token.h"
#include "netdsl/parser.h"
#include "netdsl/bpf_gen.h"
#include "sds/sds.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

static void mac_to_string(const uint8_t mac[6], char *out) {
    sprintf(out, "%02X:%02X:%02X:%02X:%02X:%02X",
            mac[0], mac[1], mac[2],
            mac[3], mac[4], mac[5]);
}

static void ipv4_to_string(const uint8_t ip[4], char *out) {
    sprintf(out, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
}

static void ipv6_to_string(const uint8_t ip[16], char *out) {
    sprintf(out,
        "%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
        "%02x%02x:%02x%02x:%02x%02x:%02x%02x",
        ip[0], ip[1], ip[2], ip[3],
        ip[4], ip[5], ip[6], ip[7],
        ip[8], ip[9], ip[10], ip[11],
        ip[12], ip[13], ip[14], ip[15]);
}

static void dump_ether(const struct ether_header *h) {
    if (!h) {
        printf("ETH(NULL)");
        return;
    }

    char src[18], dst[18];
    mac_to_string(h->src_mac, src);
    mac_to_string(h->dst_mac, dst);

    printf("ETH %s → %s", src, dst);
}

static void dump_ipv4(const struct ipv4_header *h) {
    if (!h) {
        printf(" | IPv4(NULL)");
        return;
    }

    char src[16], dst[16];
    ipv4_to_string(h->src, src);
    ipv4_to_string(h->dst, dst);

    printf(" | IPv4 %s → %s", src, dst);
}

static void dump_ipv6(const struct ipv6_header *h) {
    if (!h) {
        printf(" | IPv6(NULL)");
        return;
    }

    char src[40], dst[40];
    ipv6_to_string(h->src, src);
    ipv6_to_string(h->dst, dst);

    printf(" | IPv6 %s → %s", src, dst);
}

static void dump_tcp(const struct tcp_header *h) {
    if (!h) {
        printf(" | TCP(NULL)");
        return;
    }

    printf(" | TCP %u → %u", h->sport, h->dport);
}

static void dump_udp(const struct udp_header *h) {
    if (!h) {
        printf(" | UDP(NULL)");
        return;
    }

    printf(" | UDP %u → %u", h->sport, h->dport);
}

static void dump_arp(const struct arp_header *h) {
    if (!h) {
        printf(" | ARP(NULL)");
        return;
    }

    char sha[18], tha[18];
    char spa[16], tpa[16];

    mac_to_string(h->sha, sha);
    mac_to_string(h->tha, tha);
    ipv4_to_string(h->spa, spa);
    ipv4_to_string(h->tpa, tpa);

    if (h->op == ARP_REQUEST) {
        printf(" | ARP who-has %s? tell %s", tpa, sha);
    } else if (h->op == ARP_REPLY) {
        printf(" | ARP %s is-at %s", spa, sha);
    } else {
        printf(" | ARP op=%u", h->op);
    }
}

static void dump_node(struct proto_node *node) {
    struct proto_node *cur = node;

    while (cur) {
        switch (cur->type) {
        case PROTO_ETH:
            dump_ether((struct ether_header *)cur->hdr);
            break;

        case PROTO_IPV4:
            dump_ipv4((struct ipv4_header *)cur->hdr);
            break;

        case PROTO_IPV6:
            dump_ipv6((struct ipv6_header *)cur->hdr);
            break;

        case PROTO_TCP:
            dump_tcp((struct tcp_header *)cur->hdr);
            break;

        case PROTO_UDP:
            dump_udp((struct udp_header *)cur->hdr);
            break;

        case PROTO_ARP:
            dump_arp((struct arp_header *)cur->hdr);
            break;

        default:
            printf(" | UNKNOWN");
        }

        cur = cur->next;
    }

    printf("\n");
}

#ifdef RUN_MAIN
/*
int main() {
    const char *input = "from ip 192.8.9.0 to ip 192.123.123.123";
	struct token* tokens = malloc(sizeof(struct token) * 100);
    struct token tok;

	int i = 0;
    while ((tok = next_token(&input)).type != TOKEN_EOF) {
		*(tokens + i) = tok;
        i += 1;
    }

	struct parser_ctx ctx = {.tokens = tokens, .current = 0, .total = i};
	struct stmt* s = parse_from_stmt(&ctx);

	if (s) {
		sds buffer = sdsempty();
		int res = bpf_gen_stmt(s, &buffer);

		if (res >= 0) {
			fprintf(stdout, "%s\n", buffer);
		}
		
		free_stmt(s);
		sdsfree(buffer);
	}
	else {
		fprintf(stderr, "Couldn't parse a statement");
	}

	free(tokens);
    return 0;
}
	*/

int main(int argc, char** argv) {
	HexInstnace_t instance = create_hex_instance("en0");

	while (1) {
		struct proto_node* result = read_next_packet(&instance);
		if (result != NULL) {
			dump_node(result);
			free_packet(result);
		}
	}

	free_hex_instance(&instance);
}

#endif
