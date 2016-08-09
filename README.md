# Quagga-Graceful-Restart
Quagga Graceful Restart

Graceful Restart support is added  to quagga as specified in RFC 3623. Both the restart mode and helper mode support is added.

Configuration available
The following configurations are available under the router ospf/graceful restart node.
  disable                     disabling the status
  enable                      Enabling the status
  helper-disable              disabling the support
  helper-enable               enabling the support
  helper-strict-lsa-checking  Restart helper-strict-lsa-checking option
  no-strict-lsa-checking      Disabling helper-strict-lsa-checking option
  reason                      Restart Reason
  restart-duration            Restart interval time


Graceful Helper mode
------------------
The graceful helper mode holds the adjaceny of the gracefully restarting neighbour till the grace period expires.

Graceful Restart mode
--------------------
The gracefully restarting router informs the peers the reason for the  graceful restart,the grace period, to the peer using the type 9 opqaue lsas.
When the router restarts successfully again it flushes the grace-lsa such that the adjacent routers can exit helper mode.

Patch Detail
------------
The patch is taken from the Quagga version 0.99.24.1 as base.
