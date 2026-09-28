"""Windows asyncio IOCP Proactor resilience patch.

Fixes Python on Windows where transient client socket resets (e.g. WinError 64 / ERROR_NETNAME_DELETED,
WinError 121 / ERROR_SEM_TIMEOUT, WinError 10054 / WSAECONNRESET) during AcceptEx cause:
1. "Task exception was never retrieved" in accept_coro
2. Fatal sock.close() on the LISTENING socket in BaseProactorEventLoop._start_serving

Without this patch, whenever an endpoint client drops during accept, the server stops listening on
port 8000, causing Vite to proxy fail with ECONNREFUSED and the frontend to display 500 Internal Server Error.
"""

import logging
import sys

logger = logging.getLogger(__name__)


def install_windows_asyncio_fix() -> None:
    if sys.platform != "win32":
        return

    try:
        import asyncio.proactor_events
        import asyncio.windows_events
        import asyncio.trsock
        import asyncio.exceptions
        import asyncio.tasks

        # 1. Patch BaseProactorEventLoop._start_serving so client accept failure does not close listening socket
        orig_start_serving = asyncio.proactor_events.BaseProactorEventLoop._start_serving

        def _resilient_start_serving(self, protocol_factory, sock,
                                    sslcontext=None, server=None, backlog=100,
                                    ssl_handshake_timeout=None,
                                    ssl_shutdown_timeout=None):
            def loop(f=None):
                try:
                    if f is not None:
                        try:
                            conn, addr = f.result()
                        except OSError as client_err:
                            # Client reset/disconnected during accept (WinError 64, 121, 10054, etc.)
                            # Do NOT close listening socket! Continue accepting incoming connections.
                            logger.debug("Transient client reset during accept: %s", client_err)
                            if not self.is_closed():
                                next_f = self._proactor.accept(sock)
                                self._accept_futures[sock.fileno()] = next_f
                                next_f.add_done_callback(loop)
                            return

                        if self._debug:
                            logger.debug("%r got a new connection from %r: %r",
                                         server, addr, conn)
                        protocol = protocol_factory()
                        if sslcontext is not None:
                            self._make_ssl_transport(
                                conn, protocol, sslcontext, server_side=True,
                                extra={'peername': addr}, server=server,
                                ssl_handshake_timeout=ssl_handshake_timeout,
                                ssl_shutdown_timeout=ssl_shutdown_timeout)
                        else:
                            self._make_socket_transport(
                                conn, protocol,
                                extra={'peername': addr}, server=server)

                    if self.is_closed():
                        return
                    next_f = self._proactor.accept(sock)
                except OSError as exc:
                    if sock.fileno() != -1:
                        self.call_exception_handler({
                            'message': 'Accept failed on a socket',
                            'exception': exc,
                            'socket': asyncio.trsock.TransportSocket(sock),
                        })
                        sock.close()
                    elif self._debug:
                        logger.debug("Accept failed on socket %r",
                                     sock, exc_info=True)
                except asyncio.exceptions.CancelledError:
                    sock.close()
                else:
                    self._accept_futures[sock.fileno()] = next_f
                    next_f.add_done_callback(loop)

            self.call_soon(loop)

        asyncio.proactor_events.BaseProactorEventLoop._start_serving = _resilient_start_serving

        # 2. Patch IocpProactor.accept so accept_coro handles client disconnect cleanly without spewing warnings
        orig_accept = asyncio.windows_events.IocpProactor.accept

        def _resilient_accept(self, listener):
            self._register_with_iocp(listener)
            conn = self._get_accept_socket(listener.family)
            ov = asyncio.windows_events._overlapped.Overlapped(asyncio.windows_events.NULL)
            ov.AcceptEx(listener.fileno(), conn.fileno())

            def finish_accept(trans, key, ov):
                try:
                    ov.getresult()
                    buf = asyncio.windows_events.struct.pack('@P', listener.fileno())
                    conn.setsockopt(asyncio.windows_events.socket.SOL_SOCKET,
                                    asyncio.windows_events._overlapped.SO_UPDATE_ACCEPT_CONTEXT, buf)
                    conn.settimeout(listener.gettimeout())
                    return conn, conn.getpeername()
                except Exception:
                    try:
                        conn.close()
                    except Exception:
                        pass
                    raise

            async def accept_coro(future, conn):
                try:
                    await future
                except Exception:
                    try:
                        conn.close()
                    except Exception:
                        pass

            future = self._register(ov, listener, finish_accept)
            coro = accept_coro(future, conn)
            asyncio.tasks.ensure_future(coro, loop=self._loop)
            return future

        asyncio.windows_events.IocpProactor.accept = _resilient_accept
        logger.info("Installed Windows asyncio IOCP accept resilience patch.")
    except Exception as exc:
        logger.warning("Could not install Windows asyncio resilience patch: %s", exc)
