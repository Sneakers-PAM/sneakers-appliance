# Network settings

netd owns the box's addresses, DNS, NTP and the management firewall. Its settings are set in the
first-boot network step and later on the :8443 Network page or with `network set`, and kept in
`/var/lib/sneakers/settings/network.yaml`.

## The settings

| Setting | Values | Default |
|---|---|---|
| Management interface | the NIC 22 and 8443 listen on | the first-boot choice |
| Service interface | optional second NIC for the product's 443 and 80; 22 and 8443 never listen there | none: one NIC carries both |
| IPv4 | `dhcp`, `static` (address with prefix length, optional gateway inside it) or `off` | `dhcp` |
| IPv6 | `slaac` (also reads RDNSS), `dhcpv6`, `static` (address with prefix length, gateway link-local or inside it) or `off` | `slaac` |
| Hostname | a fully qualified name such as `appliance.example.org` | from DHCP |
| DNS | up to 3 IPv4 or IPv6 addresses, and up to 6 search domains | from DHCP and RA |
| NTP | up to 4 addresses or host names | from DHCP (option 42, DHCPv6 option 56) |
| Allow-list | the prefixes 22 and 8443 accept, without host bits | during setup any source on the management interface |
| Time zone | an IANA name such as `Europe/Paris`, or `UTC` | `UTC` |
| HTTPS proxy | an `http://` or `https://` URL without credentials | none |
| Cluster ranges | the k0s pod and service prefixes; they may not overlap each other or a static network of the box | `10.244.0.0/16` and `10.96.0.0/12`, the k0s defaults <!-- scrub:allow=private-ip --> |

At least one of IPv4 and IPv6 must be on for the management interface (and for the service interface
when there is one). A static IPv4 address can't be its subnet's network or broadcast address
(except on /31 and /32), and a static IPv6 address can't be link-local.

A setting that fails these rules is refused with `NET_INVALID`; the error names the field, such as
`management.ipv4.address` or `dns[1]`, and nothing is applied.

## Auto-revert

A change applies at once and waits 120 seconds for a confirmation from a session that still works
(the Network page, or the shell's `network set`, sends it). Without one, the previous settings are
applied again and the box records `NET_REVERTED`, so a change that cuts the admin off heals itself.
Only one change waits at a time: a second one is refused naming `pending` until the first is
confirmed or reverted. If applying a change fails outright, the previous settings are applied again
straight away and the error is returned.
