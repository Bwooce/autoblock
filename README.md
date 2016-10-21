# autoblock
Automatically block inbound traffic via net-filter combined with DNS-based blocklists

For example to add a filter on port 25, use the following command

`iptables -I INPUT -p tcp --dport 25 -j NFQUEUE --queue-balance 0:3`

(and to remove it)

`iptables -D INPUT -p tcp --dport 25 -j NFQUEUE --queue-balance 0:3`

