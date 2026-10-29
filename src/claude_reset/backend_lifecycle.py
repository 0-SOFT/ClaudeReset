"""One owned backend generation; no transition here admits Claude clients.

The platform adapter supplies protected installation checks, owned process
handles and a dynamic WFP lease. Failure always attempts every cleanup step,
revoking the lease before stopping processes. No retries or fallback routes.
"""
from .safeio import SafetyError


class Generation:
    def __init__(self, platform):
        self.platform = platform
        self.state = 'BLOCKED'
        self.lease = self.child = self.gateway = None
        self.prepared = self.closed = False

    def start(self):
        if self.prepared or self.closed: raise SafetyError('Backend generation cannot be reused')
        self.prepared = True
        self.state = 'PREPARING'
        try:
            self.platform.prepare()
            self.child = self.platform.suspended_engine()
            self.lease = self.platform.acquire_lease()
            self.platform.verify_boundary(self.lease)
            self.child.resume()
            self.gateway = self.platform.start_gateway(self.child)
            self.platform.verify_generation(self.child, self.gateway, self.lease)
            if self.platform.probe() is not True:
                raise SafetyError('Tunnel exit verification failed')
            self.platform.verify_generation(self.child, self.gateway, self.lease)
            self.state = 'BACKEND_VERIFIED_CLIENTS_CLOSED'
        except BaseException:
            self.close()
            raise
        return self.status()

    def poll(self):
        if self.state != 'BACKEND_VERIFIED_CLIENTS_CLOSED' or self.closed:
            raise SafetyError('Backend generation is not running')
        try:
            self.platform.verify_generation(self.child, self.gateway, self.lease)
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.closed: return
        self.state = 'BLOCKED'
        errors = []
        # A partially failing adapter operation must clean up resources it did
        # not return. Returned resources are owned exclusively by this object.
        # Closing the owned engine triggers the gateway's held-process health
        # check. Observe its exit afterwards; never send SCM STOP by service name.
        for resource in (self.lease, self.child, self.gateway):
            if resource is not None:
                try: resource.close()
                except BaseException as error: errors.append(type(error).__name__)
        try: self.platform.close()
        except BaseException as error: errors.append(type(error).__name__)
        self.closed = True
        if errors:
            self.state = 'BLOCKED_CLEANUP_UNCONFIRMED'
            raise SafetyError('Backend cleanup could not be confirmed: ' + ','.join(errors))

    def status(self):
        return {'schema': 1, 'state': self.state, 'client_admission': False,
                'full_tunnel_verified': False, 'closed': self.closed}

    def __enter__(self): self.start(); return self
    def __exit__(self, *args): self.close()
