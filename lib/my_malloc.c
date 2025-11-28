#define _GNU_SOURCE
#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

static void *(*real_malloc)(size_t) = NULL;
static pthread_once_t once_ctrl = PTHREAD_ONCE_INIT;

extern void *addr;                     
void *SETUP_SHADOW(void);             
void  SET_SHADOW_RANGE(void *base, void *ptr, size_t sz);

static void init_real(void) {
    real_malloc = (void *(*)(size_t))dlsym(RTLD_NEXT, "malloc");
    if (!real_malloc) {
        fprintf(stderr, "[kumpil2r] dlsym(malloc) failed: %s\n", dlerror());
        abort();
    }
}

// 패스가 치환해 호출할 대상: __mysafe_malloc(size_t)
void *__kumpil2r_malloc(size_t sz) {
    pthread_once(&once_ctrl, init_real);

    void *base = addr;
    if (!base) {
        base = SETUP_SHADOW();  
        addr = base;           
    }

    //fprintf(stderr, "[kumpil2r] detected malloc(%zu)\n", sz);
    
    void *p = real_malloc(sz+0x10); // 실제 malloc 호출

    if (p && base) {
        SET_SHADOW_RANGE(base, p, sz);  // 뒤 0x10바이트는 레드존 -> 그대로 0
    }
    
    return p;
}