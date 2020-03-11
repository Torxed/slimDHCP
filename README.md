# slimDHCP
A very slim DHCP server

binary/helpers.py
---
A way to work with bytes() and raw packets a little easier.<br>
Not saying they're perfect or make the most sense to everyone.<br>
Will be merged in/replaced in the main file eventually.

Running
-------

    sudo python slimDHCP.py --interface=ens4u1 --cache_db=session.json --filter_clients='{"00:00:00:00:00:01" : "192.168.1.5"}'

Notes
-----
There's also a extremely basic `vmlinuz-vmlinux` over `pxelinux.0` boot files to start with.
