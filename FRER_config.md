# Switch configuration for the physical experiments

Recorded from the recovery node (S4). Kontron KSwitch D10 MMT, IStaX `GA-2.02-20230614`,
Microchip LAN9668. VLAN 100 carries the protected stream, two member streams (ids 1 and 2)
enter on the two redundant ports.

```
stream 1
 dmac 02-00-00-00-00-10        ! member stream A, path S1-S2-S4
 outer-tag vid 100
stream 2
 dmac 02-00-00-00-00-10        ! member stream B, path S1-S3-S4
 outer-tag vid 100

interface GigabitEthernet 1/3
 stream-id 1
interface GigabitEthernet 1/5
 stream-id 2

tsn frer 1
 mode recovery
 ingress stream-id-list 1,2
 egress interface GigabitEthernet 1/4
 frer-vlan 100
 recovery algorithm vector history-length 16    ! default is vector, H=2
 recovery reset-timeout 1000                     ! ms
 recovery terminate                              ! strip R-Tag at egress, else the NIC drops it
 admin-state enable
```

The dmac is the listener's address; it is not secret and is reproducible by any endpoint on the
segment, which is what the injection relies on.

For the history-length sensitivity runs, `history-length 16` is changed to `8` and everything else
is kept. The MAC address above is a placeholder in the same OUI format the switch expects; put your
own listener address here.

## Things that cost me a lot of time (leave these as-is when reproducing)

- FRER generation on this platform only serves one egress port. The second member stream is
  produced with a port mirror, not by the generation function.
- A stream id may belong to only one active frer instance. Reusing an id silently gives you
  near-zero throughput and `show tsn frer 1 detail` does not tell you why.
- Set `switchport access vlan 100` before `no spanning-tree` on a port. The other order leaves the
  port in VLAN 1 with STP off, which loops against the management backbone and takes the switches
  down.
- Keep `loop-protect` off on the redundant paths. Its PDUs come back through the FRER diamond and
  the port shuts itself off.
- `egress interface GigabitEthernet 1/3,5` is accepted, `1/3,1/5` is rejected.
