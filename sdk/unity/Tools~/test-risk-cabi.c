// Actual exported C ABI invocation on the development host. No signing/key calls.
#include <assert.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef char *(*invoke_fn)(const char *,const char *);
typedef void (*free_fn)(char *);
int main(int argc,char **argv) {
    assert(argc==2);
    void *library=dlopen(argv[1],RTLD_NOW|RTLD_LOCAL);if(!library){fprintf(stderr,"%s\n",dlerror());return 1;}
    invoke_fn invoke=(invoke_fn)dlsym(library,"AppGuardUnityInvoke");
    free_fn release=(free_fn)dlsym(library,"AppGuardUnityFree");assert(invoke && release);
    const char *payloads[]={"{}","{\"expectedAppId\":\"io.appguard.host\",\"protectedResources\":{\"data/pin.json\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}}","{\"androidSignerSha256\":[\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"]}","{\"alias\":\"PRIVATE\"}","{\"expectedAppId\":null}"};
    const char *expected[]={"\"ok\":true","\"ok\":true","APPGUARD_UNSUPPORTED","APPGUARD_INVALID_INPUT","APPGUARD_INVALID_INPUT"};
    for(int i=0;i<5;i++) {
        char *buffer=invoke("scanLocalRisk",payloads[i]);assert(buffer);
        size_t length=strnlen(buffer,4097);assert(length<=4096);
        // Copy before freeing; the managed bridge follows the same ownership order.
        char *copy=malloc(length+1);assert(copy);memcpy(copy,buffer,length+1);
        // C ABI guarantees readable ownership sentinel even for the full legacy bound.
        assert(buffer[1500000]==0);release(buffer);
        assert(strstr(copy,expected[i]));assert(!strstr(copy,"PRIVATE"));
        if(i<2){assert(strstr(copy,"appguard-local-risk-v0"));assert(strstr(copy,"\"platform\":\"ios\""));}
        free(copy);
    }
    char huge[8194];memset(huge,'a',8193);huge[8193]=0;
    char *invalid=invoke("scanLocalRisk",huge);assert(invalid && strstr(invalid,"APPGUARD_INVALID_INPUT"));release(invalid);
    release(NULL);dlclose(library);
    puts("PASS: 6 actual exported C ABI scan invocations, bounded copy/readback and matching free; no key operations");
    return 0;
}
