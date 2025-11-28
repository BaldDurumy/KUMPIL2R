#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 테스트 케이스 선택을 위한 매크로
// 컴파일 시 -DTEST_CASE=N 옵션으로 선택하거나, main에서 argv로 분기

void test_stack_oob() {
    printf("[TEST] Stack OOB (Constant)\n");
    char buf[8];
    // 정상 접근
    buf[0] = 'A';
    buf[7] = 'Z';
    
    // OOB 접근 (8번째 인덱스는 크기 8 배열의 범위 밖)
    buf[8] = '!'; 
}

void test_stack_oob_dynamic() {
    printf("[TEST] Stack OOB (Dynamic)\n");
    char buf[8];
    volatile int idx = 8; // volatile을 사용하여 컴파일러 최적화 방지
    
    buf[idx] = '!';
}

void test_heap_oob() {
    printf("[TEST] Heap OOB\n");
    char *p = (char*)malloc(16);
    if (!p) return;
    
    p[0] = 'A';
    p[15] = 'Z';
    
    p[16] = '!';
    free(p);
}

void test_uaf() {
    printf("[TEST] Use-After-Free\n");
    char *p = (char*)malloc(10);
    free(p);
    
    p[0] = 'X';
}

void test_double_free() {
    printf("[TEST] Double Free\n");
    char *p = (char*)malloc(10);
    free(p);
    
    free(p); 
}

void test_uar() {
    printf("[TEST] Use-After-Return (Simulation)\n");
    // 실제 UAR은 함수 리턴 후 스택 포인터를 사용하는 것인데,
    // 현재 패스는 리턴 시 섀도우를 Clear(0으로 만듦)하므로,
    // 누군가 그 주소를 재사용하기 전까지는 'Invalid' 상태가 됨.
    // 하지만 스택 프레임이 사라지면 그 메모리는 'Unmapped'가 아니라 그냥 쓰레기 값이 됨.
    // 섀도우 메모리 상에서는 0(Invalid)이므로 접근 시 잡혀야 함.
    
    // 여기서는 억지로 흉내내기 어려우므로 생략하거나,
    // 별도 함수로 분리해야 함.
    printf("  Skipping UAR test in single function.\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <test_number>\n", argv[0]);
        printf("1: Stack OOB (Constant)\n");
        printf("2: Heap OOB\n");
        printf("3: Use-After-Free\n");
        printf("4: Double Free\n");
        printf("5: Stack OOB (Dynamic)\n");
        return 0;
    }

    int test_num = atoi(argv[1]);
    switch(test_num) {
        case 1: test_stack_oob(); break;
        case 2: test_heap_oob(); break;
        case 3: test_uaf(); break;
        case 4: test_double_free(); break;
        case 5: test_stack_oob_dynamic(); break;
        default: printf("Unknown test number\n"); break;
    }
    return 0;
}



