#!/usr/bin/env bash
set -e

# Check if build artifacts exist
if [ ! -f "./build/libkumpil2r.so" ]; then
    echo "Error: Build artifacts not found. Please run ./build.sh first."
    exit 1
fi

PASS_PLUGIN="./build/libkumpil2r.so"
RUNTIME_LIB="./build/libkumpil2r_rt.a"

function show_usage {
    echo "Usage: $0 [options] [input]"
    echo ""
    echo "Options:"
    echo "  -o <file>     Specify output file name"
    echo "  -test         Run internal test suite (no input file required)"
    echo "  -h, --help    Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 main.c -o main"
    echo "  $0 -o main main.c"
    echo "  $0 -test"
    exit 1
}

if [ "$#" -eq 0 ]; then
    show_usage
fi

MODE=""
OUTPUT_FILE=""
INPUT_FILE=""

while [[ "$#" -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_usage
            ;;
        -test)
            MODE="test"
            shift
            ;;
        -o)
            if [ -n "$2" ]; then
                OUTPUT_FILE="$2"
                shift 2
            else
                echo "Error: -o requires an argument"
                show_usage
            fi
            ;;
        *)
            if [ -z "$INPUT_FILE" ]; then
                INPUT_FILE="$1"
                shift
            else
                echo "Unknown parameter or multiple inputs: $1"
                show_usage
            fi
            ;;
    esac
done

if [ -z "$MODE" ] && [ -n "$INPUT_FILE" ] && [ -n "$OUTPUT_FILE" ]; then
    MODE="compile"
fi

if [ "$MODE" == "test" ]; then
    echo "[*] Running Tests..."
    
    # Compile test.c
    # Assuming test.c is in the current directory
    clang -O0 -fno-builtin-malloc -fno-builtin-free -emit-llvm -c test.c -o build/test.bc
    llvm-dis build/test.bc -o build/test.ll

    # Apply Pass
    opt -load-pass-plugin "$PASS_PLUGIN" -passes=kumpil2r build/test.bc -o build/kumpil2r_test.bc
    llvm-dis build/kumpil2r_test.bc -o build/kumpil2r_test.ll

    # Link
    if [ -f "$RUNTIME_LIB" ]; then
        clang build/kumpil2r_test.bc "$RUNTIME_LIB" -ldl -pthread -o output
    else
        clang build/kumpil2r_test.bc -o output
    fi

    echo "[OK] Build Complete. Running tests..."
    set +e
    
    for i in {1..5}; do
        ./output $i
        if [ $? -ne 0 ]; then
            echo "[OK]"
        else
            echo "[FAIL] Test $i did not crash"
        fi
        echo ""
    done

elif [ "$MODE" == "compile" ]; then
    echo "[*] Compiling $INPUT_FILE -> $OUTPUT_FILE"
    
    if [ ! -f "$INPUT_FILE" ]; then
        echo "Error: Input file '$INPUT_FILE' not found."
        exit 1
    fi

    BASENAME=$(basename "$INPUT_FILE" .c)
    # Handle .cpp extension as well just in case
    BASENAME=$(basename "$BASENAME" .cpp)
    BASENAME=$(basename "$BASENAME" .cc)

    # 1. Emit LLVM Bitcode
    clang -O0 -fno-builtin-malloc -fno-builtin-free -emit-llvm -c "$INPUT_FILE" -o "build/${BASENAME}.bc"
    
    # 2. Apply Pass
    opt -load-pass-plugin "$PASS_PLUGIN" -passes=kumpil2r "build/${BASENAME}.bc" -o "build/${BASENAME}.instrumented.bc"
    
    # 3. Link with Runtime
    if [ -f "$RUNTIME_LIB" ]; then
        clang "build/${BASENAME}.instrumented.bc" "$RUNTIME_LIB" -ldl -pthread -o "$OUTPUT_FILE"
    else
        clang "build/${BASENAME}.instrumented.bc" -o "$OUTPUT_FILE"
    fi
    
    echo "[OK] Generated $OUTPUT_FILE"
fi