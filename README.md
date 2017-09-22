# NdpiNfqFirewall
It is a user-space deep packet inspection tool capable of detecting and blocking of 227 application protocols.

## Why
So far there is a lack of open-source DPI tools that allow users to block packets coming from specific application.
L7filter is outdated, openappid is slow and works only with Snort, so I created this one.

## Before you start
NdpiNfqFirewall was created specificaly for a custom Linux-based OS with a patched core, therefore currently there are limitations when running on distributions with standard Linux core. Read [Limitations](#limitations) for details.

## Features
1. Processing packets from multiple queues (one queue per thread)
2. Detection of 227 supported protocols (full list can be found on [nDPI web page](http://www.ntop.org/products/deep-packet-inspection/ndpi/)).
3. Labeling connections for which the protocol detection has ended in Linux's connection tracking subsystem.
4. Periodic memory cleanup based on time flows have been idle.
5. Fully configurable parameters from the command line.
6. Printing packet header information and protocol to screen.

## Requirements
- nDPI 2.0 (make sure it's 2.0, NdpiNfqFirewall is incompatible with later versions of nDPI)
- libnetfilter_queue
- libnetfilter_conntrack

## Installation



## Limitations
