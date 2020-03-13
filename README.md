# slimDHCP
A very slim DHCP server

Running
-------

    sudo python slimDHCP.py --interface=ens4u1 --cache_db=session.json --filter_clients='{"00:00:00:00:00:01" : "192.168.1.5"}'

Notes
-----
Requires Linux and Python3.3+.<br>
There are some defaults if no options are given:

 * subnet `192.168.1.0`
 * netmask `255.255.255.0`
 * gateway `<subnet>.1` *(first avail in subnet)*
 * dns_servers `8.8.8.8` and `4.4.4.4`

Parameters
----------

All parameters must be JSON compliant.<br>
This in order for `json.loads()` to parse some of them.

```
	--cache_dir='./'
	--cache_db=null
	--subnet="192.168.1.0" ("192.168.1.0/24" is also valid and thus --netmask is ignored)
	--netmask="255.255.255.0" (/24 is also valid)
	--gateway=null (takes first available host from subnet definition)
	--is_gateway=false (more details below)
	--dns_servers="8.8.8.8,4.4.4.4" (json compliant string required)
	--pxe_bin=null
	--pxe_dir='./'
	--pxe_config=null
	--filter_clients='{"de:ad:be:ef:00:01" : true, "de:ad:be:ef:00:02" : "192.168.1.10"}'
```

There are some special flags, one such flag is `--is_gateway`.
`--is_gateway=false` simply tells slimDHCP that we're not the gateway, and thus won't give out a DHCP lease to our own MAC even if we tried.<br>
However, if we set `--is_gateway=true` and our local interface sends a DHCP request, we will hand out a lease to ourselves.
See `false` as a passive mode. And in both cases, the `gateway` ip is reserved and won't be given out.