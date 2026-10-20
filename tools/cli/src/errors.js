export class AppGuardError extends Error {
  constructor(code) { super(code); this.name='AppGuardError'; this.code=code; }
}
export function fail(code) { throw new AppGuardError(code); }
