#include <stdint.h>
#include <sys/mman.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>

#define SHADOW_OFFSET 0x100000000000

void *SETUP_SHADOW() {
    void *addr = mmap((void *)SHADOW_OFFSET,
                      0xfffffffffff,
                      PROT_READ | PROT_WRITE,
                      MAP_NORESERVE | MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                      -1, 0);

    if (addr == MAP_FAILED) {
        fprintf(stderr, "[kumpil2r] ERROR: mmap failed\n");
    }
    
    return addr;
}

void SET_SHADOW_RANGE(void *shadow_base, void *user_ptr, long size) {
    uintptr_t base = (uintptr_t)(user_ptr);
    uintptr_t end = base + (size);
    for (uintptr_t p = base; p < end; ++p) {
        uintptr_t sidx = p >> 3;
        unsigned bit = p & 7;
        ((unsigned char *)shadow_base)[sidx] |= (1 << (7 - bit));
    }
}

void CLEAR_SHADOW_RANGE(void *shadow_base, void *user_ptr, long size) {
    uintptr_t base = (uintptr_t)(user_ptr);
    uintptr_t end = base + (size);
    for (uintptr_t p = base; p < end; ++p) {
        uintptr_t sidx = p >> 3;
        unsigned bit = p & 7;
        ((unsigned char *)shadow_base)[sidx] &= ~(1 << (7 - bit));
    }
}

void VERIFY_SHADOW_MEM(void *shadow_base, void *addr, long size) {
    uintptr_t bit_start = (uintptr_t)addr;
    uintptr_t bit_end   = (uintptr_t)addr + size - 1;
    unsigned char *bitmap = (unsigned char *) shadow_base;
    size_t byte_start = bit_start >> 3;
    size_t byte_end   = bit_end >> 3;
    int bit_offset_start = bit_start % 8;
    int bit_offset_end   = bit_end % 8;

    // 양 끝 바이트의 마스크 (부분 영역)
    uint8_t mask_start = 0xFF >> bit_offset_start;
    uint8_t mask_end = 0xFF << (7 - bit_offset_end);
    
    // 단일 바이트 내에서 검사 (시작과 끝이 같음)
    if (byte_start == byte_end) {
        uint8_t mask = mask_start & mask_end;
        uint8_t bits = bitmap[byte_start] & mask;
        if (bits != mask) {
            fprintf(stderr, "[kumpil2r] ERROR: Invalid access at 0x%lx (mask=0x%02X bits=0x%02X)\n",
                    (unsigned long)addr, mask, bits);
            exit(1);
        }
        return;
    }

    // 첫 번째 바이트 검사
    if ((bitmap[byte_start] & mask_start) != mask_start) {
        fprintf(stderr, "[kumpil2r] ERROR: Invalid access at 0x%lx (partial start)\n", (unsigned long)addr);
        exit(1);
    }

    // 중간 바이트 검사
    for (size_t i = byte_start + 1; i < byte_end; i++) {
        if (bitmap[i] != 0xFF) {
            fprintf(stderr, "[kumpil2r] ERROR: Invalid access at 0x%lx (middle byte %zu)\n", (unsigned long)addr, i);
            exit(1);
        }
    }

    // 마지막 바이트 검사
    if ((bitmap[byte_end] & mask_end) != mask_end) {
        fprintf(stderr, "[kumpil2r] ERROR: Invalid access at 0x%lx (partial end)\n", (unsigned long)addr);
        exit(1);
    }
}

// ====================================================================
// GEP 추적 기반 OOB 방어를 위한 새로운 런타임 함수
void VERIFY_SHADOW_RANGE_BETWEEN(void *shadow_base, void *base_ptr, void *result_ptr) {
    uintptr_t base = (uintptr_t)base_ptr;
    uintptr_t result = (uintptr_t)result_ptr;
    
    // GEP는 일반적으로 base <= result 임을 가정합니다.
    if (result < base) {
        // base - n 접근의 경우, base가 더 클 수 있습니다.
        // 이 경우, min/max를 사용하여 작은 주소부터 큰 주소까지 검사합니다.
        uintptr_t start = result;
        uintptr_t end = base;
        
        // result부터 base까지 역방향 검사
        for (uintptr_t p = start; p <= end; ++p) {
            uintptr_t sidx = p >> 3;
            unsigned bit = p & 7;
            
            // 해당 바이트의 섀도우 비트가 0인지 확인 (0이면 무효)
            if (!(((unsigned char *)shadow_base)[sidx] & (1 << (7 - bit)))) {
                fprintf(stderr, "[kumpil2r] ERROR: Invalid access at 0x%lx (Base 0x%lx, Result 0x%lx)\n",
                        (unsigned long)p, (unsigned long)base, (unsigned long)result);
                exit(1);
            }
        }
        return;
    }

    // base + n (일반적인 GEP) 접근
    // base부터 result까지 모든 중간 바이트를 검사합니다.
    for (uintptr_t p = base; p <= result; ++p) {
        uintptr_t sidx = p >> 3;
        unsigned bit = p & 7;
        
        // 해당 바이트의 섀도우 비트가 0인지 확인 (0이면 무효)
        if (!(((unsigned char *)shadow_base)[sidx] & (1 << (7 - bit)))) {
            fprintf(stderr, "[kumpil2r] ERROR: Invalid access at 0x%lx (Base 0x%lx, Result 0x%lx)\n",
                    (unsigned long)p, (unsigned long)base, (unsigned long)result);
            exit(1);
        }
    }
}
// ====================================================================


// === 빠른 1바이트 테스트 ===
static inline int SHADOW_TEST_BYTE(void *shadow_base, const void *p) {
    uintptr_t u = (uintptr_t)p;
    unsigned char *bm = (unsigned char*)shadow_base;
    return (bm[u >> 3] & (1u << (7 - (u & 7)))) != 0;
}

// === 안전 길이 계산: NUL 또는 "읽기 불가" 전까지 ===
size_t SHADOW_STRNLEN_SAFE(void *shadow_base, const char *s, size_t hard_max) {
    size_t i = 0;
    for (; i < hard_max; i++) {
        if (!SHADOW_TEST_BYTE(shadow_base, s + i)) break; // 비가용 → 중단
        if (s[i] == '\0') break;                           // NUL → 중단
    }
    return i;
}

// === scanf("%s") 사후 검증 ===
void SCANF_POSTCHECK(void *shadow_base, char *buf, size_t hard_max) {
    for (size_t i = 0; i < hard_max; i++) {
        VERIFY_SHADOW_MEM(shadow_base, buf + i, 1);    // 접근 전 가용성 검사
        unsigned char c = (unsigned char)buf[i];       // 실제 읽기
        if (c == '\0') return;                         // OK
    }
    fprintf(stderr, "[kumpil2r] ERROR: scanf(\"%%s\"): unterminated or crossed boundary (>%zu)\n", hard_max);
    exit(1);
}

// === Double Free 탐지를 위한 유효성 검사 ===
int IS_SHADOW_VALID(void *shadow_base, void *ptr) {
    uintptr_t u = (uintptr_t)ptr;
    unsigned char *bm = (unsigned char*)shadow_base;
    return (bm[u >> 3] & (1u << (7 - (u & 7)))) != 0;
}