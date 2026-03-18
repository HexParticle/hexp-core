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

static void mac_to_string(const uint8_t mac[MAC_ADDR_LEN], char *out) {
    sprintf(out, "%02X:%02X:%02X:%02X:%02X:%02X",
            mac[0], mac[1], mac[2],
            mac[3], mac[4], mac[5]);
}

static void dump_vlan_tags(const struct vlan_tag* tags, int count) {
	for (int i = 0; i < count; i++) {
		const struct vlan_tag tag = tags[i];
		printf("   TPID: %d\n", tag.tpid);
		printf("   TCI: %d\n", tag.tci);
	}
}

static void dump_ether_header(const struct ether_header* header) {
    if (header == NULL) {
        printf("ETHER NULL\n");
        return;
    }

    char src[18];
    char dst[18];

    mac_to_string(header->src_mac, src);
    mac_to_string(header->dst_mac, dst);

    printf("Ethernet(FROM %s TO %s)\n", src, dst);

	// if (header->vlan_count > 0) {
	// 	dump_vlan_tags(header->vlans, header->vlan_count);
	// }
}

static void dump_ipv6_header(const struct ipv6_header* header) {
	if (header == NULL) {
        printf("IPv6 NULL\n");
        return;
	}

	printf("  IPv6(FROM %d.%d.%d.%d TO %d.%d.%d.%d)\n", 
			header->src[0],
			header->src[1],
			header->src[2],
			header->src[3],
			header->dst[0],
			header->dst[1],
			header->dst[2],
			header->dst[3]
	);
}

static void dump_ipv4_header(const struct ipv4_header* header) {
	if (header == NULL) {
        printf("IPv4 NULL\n");
        return;
	}

	printf("  IPv4(FROM %d.%d.%d.%d TO %d.%d.%d.%d)\n", 
			header->src[0],
			header->src[1],
			header->src[2],
			header->src[3],
			header->dst[0],
			header->dst[1],
			header->dst[2],
			header->dst[3]
	);
}

static void dump_arp_header(const struct arp_header* header) {
	if (header == NULL) {
        printf("ARP NULL\n");
        return;
	}

    char source[18];
    mac_to_string(header->sha, source);

	char target[18];
	mac_to_string(header->tha, target);

	if (header->op == ARP_REQUEST) {
		printf("  ARP(Who has %d.%d.%d.%d? Tell %s.)\n", 
			header->tpa[0],
			header->tpa[1],
			header->tpa[2],
			header->tpa[3],
			source
		);
	}
	else if (header->op == ARP_REPLY) {
		printf("  ARP(%s has %d.%d.%d.%d.)\n", 
			target, 
			header->tpa[0],
			header->tpa[1],
			header->tpa[2],
			header->tpa[3]
		);
	}
}

static void dump_tcp_header(const struct tcp_header* header) {
	if (header == NULL) {
		printf("TCP NULL\n");
		return;
	}

	printf("    TCP(FROM %d TO %d)", header->sport, header->dport);
}

static void dump_udp_header(const struct udp_header* header) {
	if (header == NULL) {
		printf("UDP NULL");
		return;
	}

	printf("    UDP(FROM %d TO %d)", header->sport, header->dport);
}

static void dump_node(struct proto_node* node) {
	struct proto_node* current_node = node;
	
	while (current_node != NULL) {
		if (current_node->type == PROTO_ETH) {
			struct ether_header* eth_hdr = (struct ether_header*) current_node->hdr;
			dump_ether_header(eth_hdr);
		}
		else if (current_node->type == PROTO_IPV4) {
			struct ipv4_header* ip_hdr = (struct ipv4_header*) current_node->hdr;
			dump_ipv4_header(ip_hdr);
		}
		else if (current_node->type == PROTO_TCP) {
			struct tcp_header* tcp_hdr = (struct tcp_header*) current_node->hdr;
			dump_tcp_header(tcp_hdr);
		}
		else if (current_node->type == PROTO_UDP) {
			struct udp_header* udp_hdr = (struct udp_header*) current_node->hdr;
			dump_udp_header(udp_hdr);
		}
		else if (current_node->type == PROTO_IPV6) {
			struct ipv6_header* ipv6 = (struct ipv6_header*) current_node->hdr;
			dump_ipv6_header(ipv6);
		}

		current_node = current_node->next;
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
