# portghost

For a dedicated interface, respond to all incoming network requests as if there as a target for it.
This can be valuable for network scans, to see what is theoretically reachable, even though the target systems are not present / configured.
Typically the setup would involve an intermdiate routing / forwarding system, which should be evaluate on it's permeability.

## Requests -> Responses

- ARP who has -> ARP is at $device_mac
- ICMP echo request -> ICMP echo reply
- TCP
  - SYN -> SYN+ACK
  - PSH -> ACK (or PSH+ACK with 1 x \x00 payload with `--tcp-psh`)
  - FIN -> FIN+ACK
- UDP -> UDP (with 1 x \x00 payload)

## Usage

```
# portghost --help
Usage: portghost [OPTIONS] <INTERFACE>

Arguments:
  <INTERFACE>  Network interface to listen on (e.g., eth0, enp0s3)

Options:
  -p, --tcp-psh                Send a null-byte in response to a TCP PSH (not just ACK)
  -A, --no-arp                 Skip responding to ARP requests
  -I, --no-icmp                Skip responding to ICMP (echo request)
  -T, --no-tcp                 Skip responding to TCP
  -U, --no-udp                 Skip responding to UDP
  -r, --drop-rst               Introduce iptables rule to drop RST packets
  -u, --drop-port-unreachable  Introduce iptables rule to drop ICMP port unreachable packets
  -h, --help                   Print help
  -V, --version                Print version
```

## iptables

Automatic system responses, like TCP RST, can be suppressed by introducing `iptables` rules.
Otherwise, the scanner could misinterpret
The following ones are available via flags on the tool:
- `--drop-rst`: Drops TCP RST packets coming from the related interface.
- `--drop-port-unreachable`: Drops ICMP port unreachable from the related interace.

## VLAN tags

If incoming packets are VLAN tagged (802.1Q), the response will replicate the VLAN tags.
