# NetDSL

```
NetDSL is a domain-specific language designed to abstract the complexities of 
network filtering and packet routing. By providing a human-readable interface, 
it allows users to define traffic policy rules that are automatically compiled 
into efficient, kernel-level BPF (Berkeley Packet Filter) syntax.
```

## Supported Syntax
* Syntax: ```FROM IP <source_ip> TO IP <destination_ip>```
* Example: ```FROM IP 192.168.1.1 TO IP 192.168.1.2```
* Generated BPF: ```src host 192.168.1.1 and dst host 192.168.1.2```
