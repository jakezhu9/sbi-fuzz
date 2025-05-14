#include <stdint.h>

int main();
extern char _stack_end;

__attribute__((optimize("O0"))) __attribute__((naked)) void _start() {
    asm volatile("la sp, _stack_end");
    main();
    while (1);
}

int __attribute__((noinline)) BREAKPOINT() {
    for (;;) {}
}

uint64_t FUZZ_INPUT[8] = {};

void sbi_call(uint64_t extension_id, uint64_t function_id, uint64_t arg0,
    uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4,
    uint64_t arg5) {
    asm volatile(
        "mv a0, %0\n"
        "mv a1, %1\n"
        "mv a2, %2\n"
        "mv a3, %3\n"
        "mv a4, %4\n"
        "mv a5, %5\n"
        "mv a6, %6\n"
        "mv a7, %7\n"
        "ecall\n": /* outpint */
        : /* input */
        "r"(arg0), "r"(arg1), "r"(arg2),
        "r"(arg3), "r"(arg4), "r"(arg5),
        "r"(function_id), "r"(extension_id): /* regs */
        "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"
    );
}

int main() {
    sbi_call(FUZZ_INPUT[0], FUZZ_INPUT[1], FUZZ_INPUT[2], FUZZ_INPUT[3],
        FUZZ_INPUT[4], FUZZ_INPUT[5], FUZZ_INPUT[6], FUZZ_INPUT[7]);
    return BREAKPOINT();
}
