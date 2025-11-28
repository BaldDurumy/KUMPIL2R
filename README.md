# KUMPIL2R (Memory Safety Sanitizer)

KUMPIL2R is an LLVM-based compiler pass that detects various memory safety errors at runtime. It instruments C/C++ code to detect:

- **Stack Out-of-Bounds (OOB)**
- **Heap Out-of-Bounds (OOB)**
- **Use-After-Free (UAF)**
- **Double Free**

It uses a Shadow Memory technique and Redzones to validate memory accesses.

## Prerequisites

- Linux Environment
- LLVM / Clang (Tested on LLVM 14+)
- CMake
- GCC / G++

## Installation & Build

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd kumpil2r
   ```

2. Build the LLVM Pass and Runtime Library:
   ```bash
   ./build.sh
   ```
   This will create a `build/` directory containing `libkumpil2r.so` (Pass) and `libkumpil2r_rt.a` (Runtime).

## Usage

Use the provided `run.sh` script to compile your code with KUMPIL2R instrumentation.

```bash
./run.sh <input_file.c> -o <output_binary>
```

Example:
```bash
./run.sh main.c -o main
./main
```

### Options
- `-o <file>` : Specify the output binary name.
- `-test` : Run the internal test suite.
- `-h` : Show help message.

## Running Tests

To verify that KUMPIL2R is working correctly, run the built-in test suite:

```bash
./run.sh -test
```

This will compile `test.c` and run 5 test cases (Stack OOB, Heap OOB, UAF, Double Free, Dynamic Stack OOB), expecting crashes or error reports for each.

## Project Structure

- `kumpil2r.cc`: The core LLVM Pass implementation.
- `lib/`: Runtime library source code (`my_malloc.c`, `my_free.c`, `shadow.c`).
- `build.sh`: Script to build the project using CMake.
- `run.sh`: Driver script to compile user code with the pass.
- `test.c`: Test cases for verification.
