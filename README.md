# tsundere
tsundere is a simple dynamic firewall with XDP

## Requirements

Kernel 5.X

## gRPC

* Ban
* Unban
* List

## CLI

```
$ tsunderectl list


$ tsunderectl ban


$ tsunderectl unban
```

## TODO


* get `perf_events` about networking
	* For example, collect `rx_packets`, `tx_packets` , `pkt/sec` per banned ip.
* DDoS auto detection & ban it
