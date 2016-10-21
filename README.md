# autoblock
Automatically block inbound traffic via [net-filter](https://home.regit.org/netfilter-en/using-nfqueue-and-libnetfilter_queue/) combined with DNS-based blocklists

For example to add a filter on port 25, use the following command

`iptables -I INPUT -p tcp --dport 25 -j NFQUEUE --queue-balance 0:3`

(and to remove it)

`iptables -D INPUT -p tcp --dport 25 -j NFQUEUE --queue-balance 0:3`


###### autobypass - recent kernels/iptables

--queue-bypass changes the behavior of an iptable rule when no userspace software is connected to the queue -- instead of dropping packets they are automatically passed. e.g. fail-safe in this context. If your system supports this I would recommend you use it.

The extension is available from Linux kernel 2.6.39 and iptables v1.4.11.

