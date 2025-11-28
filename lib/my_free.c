#define _GNU_SOURCE
#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

static void (*real_free)(void *) = NULL;
static pthread_once_t once_ctrl = PTHREAD_ONCE_INIT;

extern void *addr;                     
void *SETUP_SHADOW(void);             
void CLEAR_SHADOW_RANGE(void *base, void *ptr, size_t sz);
int IS_SHADOW_VALID(void *base, void *ptr);

static void init_real(void) {
    real_free = (void (*)(void *))dlsym(RTLD_NEXT, "free");
    if (!real_free) {
        fprintf(stderr, "[kumpil2r] dlsym(free) failed: %s\n", dlerror());
        abort();    
    }
}

void __kumpil2r_free(void *ptr) {
    pthread_once(&once_ctrl, init_real);

    void *base = addr;
    if (!base) {
        base = SETUP_SHADOW();  
        addr = base;           
    }
    
    // Double Free Check
    if (ptr && base) {
        if (!IS_SHADOW_VALID(base, ptr)) {
             fprintf(stderr, "[kumpil2r] ERROR: Double Free detected at %p\n", ptr);
             exit(1);
        }
    }

    // 청크 헤더를 통해 크기 얻기
    size_t sz = 0;

    if(ptr){
        sz = ((size_t*)ptr)[-1] & ~(size_t)0xF;
        sz = sz - 0x10;  // 헤더 크기 제외
    }

    // fprintf(stderr, "[kumpil2r] detected free(%p) of size %zu\n", ptr, sz);

    real_free(ptr); // 실제 free 호출

    if(ptr && base) {
        CLEAR_SHADOW_RANGE(base, ptr, sz);
    }

    return;
}