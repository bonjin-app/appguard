#ifndef APPGUARD_UNITY_H
#define APPGUARD_UNITY_H
#ifdef __cplusplus
extern "C" {
#endif
/* UTF8 NUL-terminated inputs (operation <=64 bytes, JSON <=1500000 bytes).
 * Each non-null response owns 1500001 readable bytes, ending in NUL.
 * Caller must release exactly once using AppGuardUnityFree, including errors.
 * NULL means allocation failure. Never pass foreign pointers to Free. */
char *AppGuardUnityInvoke(const char *operation, const char *payload);
void AppGuardUnityFree(char *response);
#ifdef __cplusplus
}
#endif
#endif
