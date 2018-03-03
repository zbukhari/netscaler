The application help is pretty well done so I don't feel the need to specify this too much.

However here's a simple statement in regards to ordering of execution.  We don't have bottled configs yet and that'll be slightly larger due to checks and balances for pre-existing items.

# Requirements

* Python 2.7
* nitro-python build 63.16 (It has to be this one which works for 10.5 and 11.0 - the one for 10.5 alone will not work due to lack of a signed certificate).

# How to get help from the application

```
# Just to get your feet wet.
$ cnvr-nitro.py -h
# Let's say you want to work with a load-balancing virtual server but want help on it.
$ cnvr-nitro.py lbvserver -h
```

# Simple load-balancing virtual server

## Steps to create a simple load-balancing virtual server.

1. add load-balancing virtual server (i.e. lbvserver)
2. add server(s) (i.e. server)
3. add service group (i.e. servicegroup)
4. bind servers to service group (i.e. servicegroup\_servicegroupmember\_binding)
5. bind (currently) built-in monitors to service group (i.e. lbmonitor\_servicegroup\_binding)
6. bind service group to load-balancing virtual server (i.e. lbvserver\_servicegroup\_binding)

## Steps to remove a simple load-balancing virtual server.

To remove it's effectively the reverse of creating a simple load-balancing virtual server.

# Other

Enjoy!

# TODO:

1. Custom monitors.
2. Content switching.
3. Enable disable action options when possible.

# Discussion

* Should I move out the classes to their own files? (for efficiencies I ran an import to create a pyc file but moving files out separately will do that - the gains are ever-so minimal but present however this may grow in time so ...)
* Enable logging perhaps if desired?
* Where should I put the binary egg file so one can install the nitro-python library?
