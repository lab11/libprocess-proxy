#!/usr/bin/env python3
import sys
import os
import socket
from tornado import gen
from tornado import httputil
from tornado.httpserver import HTTPServer
from tornado.netutil import bind_sockets
from tornado.web import RequestHandler, Application, HTTPError
from tornado.ioloop import IOLoop
import ipaddress

import argparse
class PID(object):  # noqa
  __slots__ = ('ip', 'port', 'id')

  @classmethod
  def from_string(cls, pid):
    """Parse a PID from its string representation.

    PIDs may be represented as name@ip:port, e.g.

    .. code-block:: python

        pid = PID.from_string('master(1)@192.168.33.2:5051')

    :param pid: A string representation of a pid.
    :type pid: ``str``
    :return: The parsed pid.
    :rtype: :class:`PID`
    :raises: ``ValueError`` should the string not be of the correct syntax.
    """
    try:
      id_, ip_port = pid.split('@')
      ip, port = ip_port.split(':')
      port = int(port)
    except ValueError:
      raise ValueError('Invalid PID: %s' % pid)
    return cls(ip, port, id_)

  def __init__(self, ip, port, id_):
    """Construct a pid.

    :param ip: An IP address in string form.
    :type ip: ``str``
    :param port: The port of this pid.
    :type port: ``int``
    :param id_: The name of the process.
    :type id_: ``str``
    """
    self.ip = ip
    self.port = port
    self.id = id_

  def __hash__(self):
    return hash((self.ip, self.port, self.id))

  def __eq__(self, other):
    return isinstance(other, PID) and (
      self.ip == other.ip and
      self.port == other.port and
      self.id == other.id
    )

  def __ne__(self, other):
    return not (self == other)

  def as_url(self, endpoint=None):
    url = 'http://%s:%s/%s' % (self.ip, self.port, self.id)
    if endpoint:
      url += '/%s' % endpoint
    return url

  def __str__(self):
    return '%s@%s:%d' % (self.id, self.ip, self.port)

  def __repr__(self):
    return 'PID(%s, %d, %s)' % (self.ip, self.port, self.id)

def get_ip_port(ip=None, port=None):
    ip = ip or os.environ.get('LIBPROCESS_IP', '0.0.0.0')
    try:
      port = int(port or os.environ.get('LIBPROCESS_PORT', 0))
    except ValueError:
      raise cls.Error('Invalid ip/port provided')
    return ip, port

def make_socket(ip, port):
    """Bind to a new socket.

    If LIBPROCESS_PORT or LIBPROCESS_IP are configured in the environment,
    these will be used for socket connectivity.
    """
    bound_socket = bind_sockets(port, address=ip)[0]
    ip, port = bound_socket.getsockname()

    if not ip or ip == '0.0.0.0':
      ip = socket.gethostbyname(socket.gethostname())

    return bound_socket, ip, port

class ProxyRequestHandler(RequestHandler):

  def __init__(self, master_ip):
    RequestHandler.__init__(self)
    self.master = master_ip

  @classmethod
  def detect_from_process(cls, headers):
    """Returns tuple of process, legacy or None, None if not process originating."""

    try:
      if 'Libprocess-From' in headers:
        return PID.from_string(headers['Libprocess-From']), False
      elif 'User-Agent' in headers and headers['User-Agent'].startswith('libprocess/'):
        return PID.from_string(headers['User-Agent'][len('libprocess/'):]), True
    except ValueError as e:
      print('Failed to detect process: %r' % e)
      pass

    return None, None

  def detect_to_process_id(cls, headers):
    print(headers)
    return None, None

  def post(self, *args, **kw):
    #detect the process that this is from
    print("Received post")
    process, legacy = self.detect_from_process(self.request.headers)
    print(process,self.request.remote_ip,self.request.connection.stream.socket.getpeername())

    if process is None:
      #if non send back a 404, this isn't a valid libprocess message
      self.set_status(404)
      self.finish()
      return
    
    #was this sent from the target server or the outside world?
    if process.ip == self.master:
      #This message was from the master we are proxying, we should do the
      #lookup and forward it back to the outside world
      print("Received post from master destined for: " + self.detect_to_process_id(self.request.headers))
    elif ipaddress.ip_address(process.ip).is_private:
      #This message is from a device behind a NAT, we should replace the
      #source IP with our own and add it to the map
      print("Received post from private IP: " + process.ip)
    else:
      #not the master but from a public IP, we should be able to just forward it
      #directly
      print("Received post from public IP: " + process.ip)

  #def send(self, request, destination_ip, destination_port):
    #connect to ip and port if necessary
    #stream write request to that IP/port


# def send(self, from_pid, to_pid, method, body=None):
#    """Send a message method from one pid to another with an optional body.
#
#    Note: It is more idiomatic to send directly from a bound process rather than
#    calling send on the context.
#
#    If the destination pid is on the same context, the Context may skip the
#    wire and route directly to process itself.  ``from_pid`` must be bound
#    to this context.
#
#    This method returns immediately.
#
#    :param from_pid: The pid of the sending process.
#    :type from_pid: :class:`PID`
#    :param to_pid: The pid of the destination process.
#    :type to_pid: :class:`PID`
#    :param method: The method name of the destination process.
#    :type method: ``str``
#    :keyword body: Optional content to send along with the message.
#    :type body: ``bytes`` or None
#    :return: Nothing
#    """
#
#    self._assert_started()
#    self._assert_local_pid(from_pid)
#
#    if self._is_local(to_pid):
#      local_method = self._get_local_mailbox(to_pid, method)
#      if local_method:
#        log.info('Doing local dispatch of %s => %s (method: %s)' % (from_pid, to_pid, local_method))
#        self.__loop.add_callback(local_method, from_pid, body or b'')
#        return
#      else:
#        # TODO(wickman) Consider failing hard if no local method is detected, otherwise we're
#        # just going to do a POST and have it dropped on the floor.
#        pass
#
#    request_data = encode_request(from_pid, to_pid, method, body=body)
#
#    log.info('Sending POST %s => %s (payload: %d bytes)' % (
#             from_pid, to_pid.as_url(method), len(request_data)))
#
#    def on_connect(stream):
#      log.info('Writing %s from %s to %s' % (len(request_data), from_pid, to_pid))
#      stream.write(request_data)
#      log.info('Wrote %s from %s to %s' % (len(request_data), from_pid, to_pid))
#
#    self.__loop.add_callback(self._maybe_connect, to_pid, on_connect)

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='Libprocess proxy')
    parser.add_argument('master', type=str,  help='The IP address being proxied (where are messages from the outside world being forwarded?)')
    args = parser.parse_args()


    #Bind to your external socket and port
    ip, port = get_ip_port()
    sock, ip, port = make_socket(ip, port)

    #start the tornado server on the SOCKET and port
    app = Application(handlers=[(r'.*', ProxyRequestHandler(args.master))])
    server = HTTPServer(app)
    server.add_sockets([sock])
    print("Listening on " + str(ip) + ":" + str(port))
    sock.listen(1024)

    #start the IO loop
    IOLoop.current().start()
