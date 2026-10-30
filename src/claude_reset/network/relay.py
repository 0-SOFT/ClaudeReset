"""The loopback relay Claude's clients talk to: it accepts only verified local peers and forwards their
connections upstream."""
import os
import select
import socket
import threading

from .. import config
from ..errors import SafetyError

__all__ = ['Relay']


class Relay:
    def __init__(self, upstream, verify_peer, *, port=config.RELAY_PORT):
        self.upstream, self.verify_peer = upstream, verify_peer
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if os.name == 'nt':
            self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        self.listener.bind((config.LOOPBACK, port))
        self.listener.listen(32)
        self.listener.settimeout(.5)
        self.port = self.listener.getsockname()[1]
        self.stopped = threading.Event()
        self.clients = set()
        self.lock = threading.Lock()
        self.slots = threading.BoundedSemaphore(64)

    def serve(self):
        while not self.stopped.is_set():
            try:
                client, address = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            if not self.slots.acquire(False):
                client.close()
                continue
            with self.lock:
                if self.stopped.is_set():
                    client.close()
                    self.slots.release()
                    break
                self.clients.add(client)
            threading.Thread(target=self._pipe, args=(client,), daemon=True).start()

    def _pipe(self, client):
        upstream = None
        try:
            upstream = socket.create_connection(self.upstream, timeout=5)
            # The listener could have been replaced after a process crash. A
            # port check alone is insufficient: verify the accepted socket PID.
            if not self.verify_peer(upstream):
                return
            with self.lock:
                if self.stopped.is_set():
                    return
                self.clients.add(upstream)
            client.settimeout(5)
            while not self.stopped.is_set():
                readable, _, _ = select.select([client, upstream], [], [], .5)
                for source in readable:
                    data = source.recv(32768)
                    if not data or self.stopped.is_set():
                        return
                    (upstream if source is client else client).sendall(data)
        except (OSError, SafetyError, ValueError):
            pass  # No direct retry, redirect, or alternate upstream.
        finally:
            with self.lock:
                for stream in (client, upstream):
                    if stream is not None:
                        self.clients.discard(stream)
                        stream.close()
            self.slots.release()

    def close(self):
        self.stopped.set()
        self.listener.close()
        with self.lock:
            for stream in tuple(self.clients):
                try:
                    stream.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                stream.close()
            self.clients.clear()
