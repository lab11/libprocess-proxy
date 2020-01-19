import logging
import re
import types
import time

from .pid import PID

try:
  import asyncio
except ImportError:
  import trollius as asyncio



from tornado import gen
from tornado import httputil
from tornado.httpserver import HTTPServer
from tornado.web import RequestHandler, Application, HTTPError


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

  @classmethod
  def detect_process(cls, headers):
    """Returns tuple of process, legacy or None, None if not process originating."""

    try:
      if 'Libprocess-From' in headers:
        return PID.from_string(headers['Libprocess-From']), False
      elif 'User-Agent' in headers and headers['User-Agent'].startswith('libprocess/'):
        return PID.from_string(headers['User-Agent'][len('libprocess/'):]), True
    except ValueError as e:
      log.error('Failed to detect process: %r' % e)
      pass

    return None, None

  def post(self, *args, **kw):
    #detect the process that this is from
    process, legacy = self.detect_process(self.request.headers)

    if process is None:
      #if non send back a 404, this isn't a valid libprocess message
      self.set_status(404)
      self.finish()
      return
    
    #was this sent from the target server or the outside world?

    #if it was sent from the outside world
      #Note the public IP/PORT pair
      #Create a unique from PID that identifies the originator of the message
      #proxy_ip:proxy_port/public_ip
  
    #get the public IP/port pair that this was sent from

    log.debug('Delivering %s to %s from %s' % (self.__name, self.process.pid, process))
    log.debug('Request body length: %s' % len(self.request.body))

    # Handle the message
    self.process.handle_message(self.__name, process, self.request.body)

    self.set_status(202)
    self.finish()

 def send(self, from_pid, to_pid, method, body=None):
    """Send a message method from one pid to another with an optional body.

    Note: It is more idiomatic to send directly from a bound process rather than
    calling send on the context.

    If the destination pid is on the same context, the Context may skip the
    wire and route directly to process itself.  ``from_pid`` must be bound
    to this context.

    This method returns immediately.

    :param from_pid: The pid of the sending process.
    :type from_pid: :class:`PID`
    :param to_pid: The pid of the destination process.
    :type to_pid: :class:`PID`
    :param method: The method name of the destination process.
    :type method: ``str``
    :keyword body: Optional content to send along with the message.
    :type body: ``bytes`` or None
    :return: Nothing
    """

    self._assert_started()
    self._assert_local_pid(from_pid)

    if self._is_local(to_pid):
      local_method = self._get_local_mailbox(to_pid, method)
      if local_method:
        log.info('Doing local dispatch of %s => %s (method: %s)' % (from_pid, to_pid, local_method))
        self.__loop.add_callback(local_method, from_pid, body or b'')
        return
      else:
        # TODO(wickman) Consider failing hard if no local method is detected, otherwise we're
        # just going to do a POST and have it dropped on the floor.
        pass

    request_data = encode_request(from_pid, to_pid, method, body=body)

    log.info('Sending POST %s => %s (payload: %d bytes)' % (
             from_pid, to_pid.as_url(method), len(request_data)))

    def on_connect(stream):
      log.info('Writing %s from %s to %s' % (len(request_data), from_pid, to_pid))
      stream.write(request_data)
      log.info('Wrote %s from %s to %s' % (len(request_data), from_pid, to_pid))

    self.__loop.add_callback(self._maybe_connect, to_pid, on_connect)

if __name__ == "__main__":
    #Bind to your external socket and port
    ip, port = self.get_ip_port(ip, port)
    sock, ip, port = self.make_socket(ip, port)

    # The entry point of the Context thread.  This should not be called directly.
    loop = asyncio.new_event_loop()

    class CustomIOLoop(BaseAsyncIOLoop):
      def initialize(self):
        super(CustomIOLoop, self).initialize(loop, close_loop=False)

    loop = CustomIOLoop()

    #start the tornado server on the SOCKET and port
    app = Application(handlers=[(r'*', ProxyRequestHandler)])
    server = HTTPServer(app, io_loop=loop)
    server.add_sockets([sock])

    sock.listen(1024)

    loop.start()
    loop.close()

