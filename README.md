# slimDHCP
A very slim DHCP server

binary/helpers.py
---
A way to work with bytes() and raw packets a little easier.
Not saying they're perfect or make the most sense to everyone.

But I like looking at packets in binary form to make sense of them.

Running
-------

    python slimDHCP.py  (no external dependencies)

hosting files
-------------

everything in `./tftp/` can be placed anywhere,
but the recommendation is `/srv/tftp/`.

Then simply point your tftp server to that directory.
For convencience, there's a `tftp.py` included that you can run with:

    python tftp.py

This will host anything under `/srv/tftp/` over the TFTP protocol.
(a bit shaky, but will do the trick)

There's also a extremely basic `vmlinuz-vmlinux` over `pxelinux.0` boot files to start with.