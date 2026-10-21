import { VerificationError, reject } from './errors.js';

export function connectionClosed(req, res) {
  // IncomingMessage.close/destroyed can mean a normally completed body.
  return Boolean(req.aborted || req.socket?.destroyed || res.destroyed || res.writableEnded);
}

/** Private per-enforcement lifetime; never cancels application/backend work. */
export function watchConnection(req, res) {
  const socket = req.socket;
  const waiters = new Set();
  let stopped = false;
  const stop = () => {
    stopped = true;
    const pending = [...waiters];
    waiters.clear();
    for (const cancel of pending) cancel();
  };
  const check = () => {
    if (stopped || connectionClosed(req, res)) { stop(); reject(); }
  };
  const watch = cancel => {
    waiters.add(cancel);
    if (stopped || connectionClosed(req, res)) stop();
    return () => waiters.delete(cancel);
  };
  res.once('close', stop);
  req.once('aborted', stop);
  socket?.once('close', stop);
  return {
    check, watch,
    wait(operation) {
      return new Promise((resolve, fail) => {
        let settled = false, unwatch = () => {};
        const finish = (settle, value) => {
          if (settled) return;
          settled = true; unwatch(); settle(value);
        };
        unwatch = watch(() => finish(fail, new VerificationError('INVALID_REQUEST')));
        // Both branches remain observed if the connection wins this race.
        Promise.resolve().then(() => { check(); return operation(); })
          .then(value => finish(resolve, value), error => finish(fail, error));
      });
    },
    dispose() {
      res.removeListener('close', stop);
      req.removeListener('aborted', stop);
      socket?.removeListener('close', stop);
      stop();
    },
  };
}
