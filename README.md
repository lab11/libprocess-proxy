# libprocess-proxy
A server-side proxy for libprocess. Allows libprocess communication with devices that are behind a NAT. 

[Libprocess](https://github.com/apache/mesos/tree/master/3rdparty/libprocess)
is an abstraction and library which supports asynchronous programming. It was created
for and is used by Apache Mesos.

The libprocess protocol was fundamentally not designed to be used by processes
behind a NAT. The originating process encodes its own IP address in a request
header, and therefore a receiving process cannot respond to this IP address if
it is a private address.

This proxy is intended to address this problem. It receives libprocess messages and
sends them on to a fixed IP address, replacing the IP header with its own
header and a unique port. When it receives a response it will forward that response
on to the correct public IP address or the originating message.

## Usage

## Options
LIBPROCESS_IP
LIBPROCESS_PORT
LIBPROCESS_ADVERTISE_IP
LIBPROCESS_ADVERTISE_PORT
LIBPROCESS_PROXY_ENDPOINT
