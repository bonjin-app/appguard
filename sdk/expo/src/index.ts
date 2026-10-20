import { requireOptionalNativeModule } from 'expo';
import { createClient, type NativeBridge } from './client';
export { AppGuardError } from './client';
export type { HardwareRequirement, KeyOptions, PublicKeyResult, PrepareInput, PreparedRequest, EnrollmentChallenge, EnrollmentInput, EnrollmentResult, AppGuardErrorCode } from './client';
const client = createClient(() => requireOptionalNativeModule<NativeBridge>('AppGuard'));
export const publicKey = client.publicKey;
export const prepare = client.prepare;
export const enrollmentProof = client.enrollmentProof;
