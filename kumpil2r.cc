#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/Support/Alignment.h"
#include "llvm/Support/raw_ostream.h"

#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/Config/llvm-config.h"

#include <vector>
#include <string>
#include <cctype>
#include <cstring>
#include <algorithm>
#include <functional>

using namespace llvm;

namespace {

// ====================================================================
// Helper Functions
// ====================================================================

static bool getConstCString(Value *V, std::string &Out) {
    V = V->stripPointerCasts();
    if (auto *GV = dyn_cast<GlobalVariable>(V)) {
        if (GV->hasInitializer()) {
            if (auto *CDA = dyn_cast<ConstantDataArray>(GV->getInitializer())) {
                if (CDA->isString()) {
                    StringRef S = CDA->getAsString();
                    Out = S.str();
                    if (!Out.empty() && Out.back() == '\0') Out.pop_back();
                    return true;
                }
            }
        }
    }
    return false;
}

static std::pair<std::string, std::vector<unsigned>>
rewritePrintfToDotStarForS(StringRef Fmt) {
    std::string out;
    std::vector<unsigned> insertBeforeArgIdx;
    unsigned curArg = 1;

    for (size_t i = 0, n = Fmt.size(); i < n; ) {
        if (Fmt[i] != '%') { out.push_back(Fmt[i++]); continue; }
        if (i + 1 < n && Fmt[i+1] == '%') { out.append("%%"); i += 2; continue; }

        out.push_back('%'); ++i;
        while (i < n && std::strchr("+- #0", Fmt[i])) { out.push_back(Fmt[i]); ++i; }
        if (i < n && Fmt[i] == '*') { out.push_back('*'); ++i; ++curArg; }
        else { while (i < n && std::isdigit((unsigned char)Fmt[i])) { out.push_back(Fmt[i]); ++i; } }

        bool hasPrecision = false;
        if (i < n && Fmt[i] == '.') {
            hasPrecision = true; out.push_back('.'); ++i;
            if (i < n && Fmt[i] == '*') { out.push_back('*'); ++i; ++curArg; }
            else { while (i < n && std::isdigit((unsigned char)Fmt[i])) { out.push_back(Fmt[i]); ++i; } }
        }

        while (i < n && std::strchr("hljztL", Fmt[i])) { out.push_back(Fmt[i]); ++i; }

        if (i >= n) break;
        char conv = Fmt[i++];

        if (conv == 's') {
            if (!hasPrecision) { out.append(".*"); insertBeforeArgIdx.push_back(curArg); }
            out.push_back('s');
            ++curArg;
        } else {
            out.push_back(conv);
            ++curArg;
        }
    }
    return {out, insertBeforeArgIdx};
}

static std::vector<std::pair<unsigned,int>>
getScanfSArgsAndWidths(StringRef Fmt) {
    std::vector<std::pair<unsigned,int>> out;
    unsigned curArg = 1;
    for (size_t i = 0, n = Fmt.size(); i < n; ) {
        if (Fmt[i] != '%') { ++i; continue; }
        if (i+1 < n && Fmt[i+1] == '%') { i += 2; continue; }
        ++i;
        bool suppress = false;
        if (i < n && Fmt[i] == '*') { suppress = true; ++i; }

        int width = -1;
        if (i < n && std::isdigit((unsigned char)Fmt[i])) {
            width = 0;
            while (i < n && std::isdigit((unsigned char)Fmt[i])) {
                width = width * 10 + (Fmt[i] - '0'); ++i;
            }
        }

        auto take = [&](char c){ if (i < n && Fmt[i]==c){ ++i; return true; } return false; };
        if (take('h')) (void)take('h');
        else if (take('l')) (void)take('l');
        else { (void)take('j'); (void)take('z'); (void)take('t'); (void)take('L'); }

        if (i >= n) break;
        char conv = Fmt[i++];

        if (conv == 'n') {
            if (!suppress) ++curArg;
            continue;
        }

        if (conv == 's' || conv == '[') {
            if (!suppress) {
                out.emplace_back(curArg, width);
                ++curArg;
            }
        } else if (conv == 'c' || conv == 'C') {
             if (!suppress) ++curArg;
        } else {
            if (!suppress) ++curArg;
        }
    }
    return out;
}

static unsigned countPercentS(StringRef Fmt) {
    unsigned cnt = 0;
    for (size_t i = 0; i + 1 < Fmt.size(); ) {
        if (Fmt[i] != '%') { ++i; continue; }
        if (Fmt[i+1] == '%') { i += 2; continue; }
        size_t j = i + 1;
        while (j < Fmt.size() && std::strchr("+- #0", Fmt[j])) ++j;
        while (j < Fmt.size() && (std::isdigit((unsigned char)Fmt[j]) || Fmt[j] == '*')) ++j;
        if (j < Fmt.size() && Fmt[j] == '.') {
            ++j; if (j < Fmt.size() && Fmt[j] == '*') ++j; else while (j < Fmt.size() && std::isdigit((unsigned char)Fmt[j])) ++j;
        }
        while (j < Fmt.size() && std::strchr("hljztL", Fmt[j])) ++j;
        if (j < Fmt.size() && Fmt[j] == 's') { ++cnt; ++j; }
        i = j;
    }
    return cnt;
}

static Value *findBasePtr(Value *V, const DataLayout &DL, DenseSet<Value*>& Visited) {
    if (!V) return nullptr;
    if (Visited.count(V)) return nullptr;
    Visited.insert(V);

    // errs() << "[DEBUG] findBasePtr visiting: " << *V << "\n";

    if (isa<AllocaInst>(V)) return V;
    if (isa<GlobalVariable>(V)) return nullptr;
    if (isa<Argument>(V)) return V;
    if (isa<ConstantPointerNull>(V)) return nullptr;
    if (isa<CallBase>(V)) return V;

    if (auto *GEP = dyn_cast<GetElementPtrInst>(V)) {
        return findBasePtr(GEP->getPointerOperand(), DL, Visited);
    }

    if (auto *PTI = dyn_cast<PtrToIntInst>(V)) {
        return PTI->getOperand(0);
    }

    if (auto *LI = dyn_cast<LoadInst>(V)) {
        Value *Ptr = LI->getPointerOperand();
        if (auto *AI = dyn_cast<AllocaInst>(Ptr)) {
            for (User *U : AI->users()) {
                if (StoreInst *SI = dyn_cast<StoreInst>(U)) {
                    if (SI->getPointerOperand() == AI) {
                        // errs() << "[DEBUG] findBasePtr found store: " << *SI << "\n";
                        Value *Result = findBasePtr(SI->getValueOperand(), DL, Visited);
                        if (Result) return Result;
                    }
                }
            }
        }
        return nullptr; // Stop if we can't trace the load
    }

    if (auto *BO = dyn_cast<BinaryOperator>(V)) {
        Value *Op0 = BO->getOperand(0);
        Value *Op1 = BO->getOperand(1);
        if (!isa<ConstantInt>(Op0)) {
            if (Value *Result = findBasePtr(Op0, DL, Visited)) return Result;
        }
        if (!isa<ConstantInt>(Op1)) {
            if (Value *Result = findBasePtr(Op1, DL, Visited)) return Result;
        }
    }

    if (auto *CI = dyn_cast<CastInst>(V)) {
        if (isa<IntToPtrInst>(CI)) return nullptr;
        return findBasePtr(CI->getOperand(0), DL, Visited);
    }

    if (auto *Inst = dyn_cast<Instruction>(V)) {
        if (Inst->getNumOperands() == 1) {
            return findBasePtr(Inst->getOperand(0), DL, Visited);
        }
    }

    return nullptr;
}

// ====================================================================
// MyPass Class
// ====================================================================

class MyPass : public PassInfoMixin<MyPass> {
    // Cached Types
    IntegerType *I8Ty = nullptr;
    IntegerType *I32Ty = nullptr;
    IntegerType *I64Ty = nullptr;
    Type *VoidTy = nullptr;
    PointerType *PtrTy = nullptr;

    // Runtime Functions
    FunctionCallee SetupFn;
    FunctionCallee SetShadowFn;
    FunctionCallee ClearShadowFn;
    FunctionCallee VerifyFn;
    FunctionCallee VerifyRangeFn;
    FunctionCallee StrnSafeFn;
    FunctionCallee ScanfPostFn;
    FunctionCallee MyMallocFn;
    FunctionCallee MyFreeFn;
    FunctionCallee PrintfFn;
    FunctionCallee ExitFn;

    GlobalVariable *AddrGV = nullptr;

public:
    PreservedAnalyses run(Module &M, ModuleAnalysisManager &) {
        initializeTypes(M);
        initializeCallbacks(M);

        AddrGV = M.getNamedGlobal("addr");
        if (!AddrGV) {
            AddrGV = new GlobalVariable(
                M, PtrTy, /*isConstant=*/false, GlobalValue::ExternalLinkage,
                ConstantPointerNull::get(PtrTy), "addr");
        }

        for (Function &F : M) {
            if (F.isDeclaration()) continue;
            processFunction(F, M.getDataLayout());
        }

        return PreservedAnalyses::none();
    }

private:
    void initializeTypes(Module &M) {
        LLVMContext &Ctx = M.getContext();
        I8Ty = Type::getInt8Ty(Ctx);
        I32Ty = Type::getInt32Ty(Ctx);
        I64Ty = Type::getInt64Ty(Ctx);
        VoidTy = Type::getVoidTy(Ctx);
        PtrTy = PointerType::get(Ctx, 0);
    }

    void initializeCallbacks(Module &M) {
        LLVMContext &Ctx = M.getContext();
        
        SetupFn = M.getOrInsertFunction("SETUP_SHADOW", FunctionType::get(PtrTy, {}, false));
        SetShadowFn = M.getOrInsertFunction("SET_SHADOW_RANGE", FunctionType::get(VoidTy, {PtrTy, PtrTy, I64Ty}, false));
        ClearShadowFn = M.getOrInsertFunction("CLEAR_SHADOW_RANGE", FunctionType::get(VoidTy, {PtrTy, PtrTy, I64Ty}, false));
        VerifyFn = M.getOrInsertFunction("VERIFY_SHADOW_MEM", FunctionType::get(VoidTy, {PtrTy, PtrTy, I64Ty}, false));
        VerifyRangeFn = M.getOrInsertFunction("VERIFY_SHADOW_RANGE_BETWEEN", FunctionType::get(VoidTy, {PtrTy, PtrTy, PtrTy}, false));
        StrnSafeFn = M.getOrInsertFunction("SHADOW_STRNLEN_SAFE", FunctionType::get(I64Ty, {PtrTy, PtrTy, I64Ty}, false));
        ScanfPostFn = M.getOrInsertFunction("SCANF_POSTCHECK", FunctionType::get(VoidTy, {PtrTy, PtrTy, I64Ty}, false));

        // MyMalloc
        auto *SizeT = IntegerType::get(Ctx, M.getDataLayout().getPointerSizeInBits());
        MyMallocFn = M.getOrInsertFunction("__kumpil2r_malloc", FunctionType::get(PtrTy, {SizeT}, false));

        // MyFree
        MyFreeFn = M.getOrInsertFunction("__kumpil2r_free", FunctionType::get(VoidTy, {PtrTy}, false));

        // Printf & Exit for Array Bounds Check
        PrintfFn = M.getOrInsertFunction("printf", FunctionType::get(I32Ty, {PtrTy}, true));
        ExitFn = M.getOrInsertFunction("exit", FunctionType::get(VoidTy, {I32Ty}, false));
    }

    bool isSafeStaticAccess(Value *Ptr, uint64_t AccessSize, const DataLayout &DL) {
        Ptr = Ptr->stripPointerCasts();
        APInt Offset(64, 0);
        Value *Base = Ptr->stripAndAccumulateConstantOffsets(DL, Offset, /*AllowNonInbounds*/ true);
        
        uint64_t ObjectSize = 0;

        if (auto *AI = dyn_cast<AllocaInst>(Base)) {
            if (AI->isArrayAllocation()) {
                 if (auto *CI = dyn_cast<ConstantInt>(AI->getArraySize())) {
                     ObjectSize = CI->getZExtValue() * DL.getTypeAllocSize(AI->getAllocatedType());
                 } else {
                     return false; 
                 }
            } else {
                ObjectSize = DL.getTypeAllocSize(AI->getAllocatedType());
            }
        } else if (auto *GV = dyn_cast<GlobalVariable>(Base)) {
            if (GV->getValueType()->isSized()) {
                ObjectSize = DL.getTypeAllocSize(GV->getValueType());
            } else {
                return false;
            }
        } else {
            return false;
        }

        if (Offset.isNonNegative()) {
            uint64_t Off = Offset.getZExtValue();
            if (Off + AccessSize <= ObjectSize) {
                return true;
            }
        }
        return false;
    }

    bool handleArrayAccess(GetElementPtrInst *GEP, Function &F, const DataLayout &DL) {
        Type *ElementType = GEP->getSourceElementType();
        auto *ArrType = dyn_cast<ArrayType>(ElementType);
        if (!ArrType) return false;

        uint64_t ArrSize = ArrType->getNumElements();
        Value *Index = GEP->getOperand(GEP->getNumOperands() - 1);

        // 1. Constant Index Check (Only for Warnings)
        // Safe constants are handled by isSafeStaticAccess before this function is called.
        if (auto *ConstIdx = dyn_cast<ConstantInt>(Index)) {
            int64_t idx_val = ConstIdx->getSExtValue();
            if (idx_val < 0 || idx_val >= (int64_t)ArrSize) {
                errs() << "[kumpil2r] WARNING: Array index " << idx_val << " is out of bounds (0 ~ " << ArrSize - 1 << ") in function " << F.getName() << "\n";
            }
            // Fallthrough to generate runtime check (which will trap for unsafe constants)
        }

        // 2. Runtime Index Check
        IRBuilder<> Builder(GEP);
        Value *Zero = Builder.getInt64(0);
        Value *Limit = Builder.getInt64(ArrSize);
        
        Value *Idx64 = Builder.CreateSExtOrBitCast(Index, I64Ty);

        Value *LowerBound = Builder.CreateICmpSLT(Idx64, Zero);
        Value *UpperBound = Builder.CreateICmpSGE(Idx64, Limit);
        Value *OOB = Builder.CreateOr(LowerBound, UpperBound);

        Instruction *SplitPt = GEP;
        BasicBlock *OrigBB = GEP->getParent();
        BasicBlock *ContBB = OrigBB->splitBasicBlock(SplitPt, "cont");
        BasicBlock *ThenBB = BasicBlock::Create(F.getContext(), "oob", &F);

        IRBuilder<> ThenBuilder(ThenBB);
        Value *FmtStr = ThenBuilder.CreateGlobalStringPtr("[kumpil2r] ERROR: Array index out of bounds (Limit %ld)\n");
        ThenBuilder.CreateCall(PrintfFn, {FmtStr, Limit});
        ThenBuilder.CreateCall(ExitFn, {ThenBuilder.getInt32(1)});
        ThenBuilder.CreateUnreachable();

        OrigBB->getTerminator()->eraseFromParent();
        IRBuilder<> BranchBuilder(OrigBB);
        BranchBuilder.CreateCondBr(OOB, ThenBB, ContBB);

        return true;
    }

    void processFunction(Function &F, const DataLayout &DL) {
        IRBuilder<> EntryB(&*F.getEntryBlock().getFirstInsertionPt());
        Value *ShadowBase = nullptr;

        if (F.getName() == "main") {
            ShadowBase = EntryB.CreateCall(SetupFn);
            EntryB.CreateStore(ShadowBase, AddrGV);
        } else {
            ShadowBase = EntryB.CreateLoad(PtrTy, AddrGV);
        }

        std::vector<AllocaInst *> Allocas;
        std::vector<IntToPtrInst*> IntToPtrs;
        std::vector<GetElementPtrInst*> Geps;
        std::vector<CallBase*> CallsToReplace;
        DenseSet<Instruction*> SkipInsts;
        DenseSet<Value*> SafeGEPs;

        for (BasicBlock &BB : F) {
            for (Instruction &I : BB) {
                if (auto *CB = dyn_cast<CallBase>(&I)) {
                    CallsToReplace.push_back(CB);
                } else if (auto *AI = dyn_cast<AllocaInst>(&I)) {
                    Allocas.push_back(AI);
                    AI->setAlignment(Align(1));
                } else if (auto *ITP = dyn_cast<IntToPtrInst>(&I)) {
                    IntToPtrs.push_back(ITP);
                } else if (auto *G = dyn_cast<GetElementPtrInst>(&I)) {
                    Geps.push_back(G);
                }
            }
        }

        // 1. Handle Calls
        for (auto *CB : CallsToReplace) {
            handleCall(CB, ShadowBase);
        }

        // 2. Handle Allocas
        if (!Allocas.empty()) {
            handleAllocas(Allocas, ShadowBase, DL, F, SkipInsts);
        }

        // 3. Handle GEPs
        for (auto *G : Geps) {
            // [Optimization] Static Analysis
            // If the GEP result is statically within the bounds of the base object, we can skip runtime check.
            if (isSafeStaticAccess(G, 1, DL)) {
                SafeGEPs.insert(G);
                continue;
            }

            if (handleArrayAccess(G, F, DL)) {
                SafeGEPs.insert(G);
            } else {
                handleGEP(G, ShadowBase, DL);
            }
        }

        // 4. Handle IntToPtr
        for (auto *ITP : IntToPtrs) {
            handleIntToPtr(ITP, ShadowBase, DL);
        }

        // 5. Handle Loads/Stores
        for (BasicBlock &BB : F) {
            DenseSet<Value*> VerifiedPtrs;
            for (Instruction &I : BB) {
                if (SkipInsts.count(&I)) continue;

                if (auto *LI = dyn_cast<LoadInst>(&I)) {
                    if (auto *LIPtr = dyn_cast<LoadInst>(ShadowBase)) {
                        if (LI == LIPtr) continue;
                    }
                    if (isAddrGlobalPtr(LI->getPointerOperand())) continue;
                    
                    Value *Ptr = LI->getPointerOperand();
                    if (VerifiedPtrs.count(Ptr)) continue;
                    if (SafeGEPs.count(Ptr)) continue;

                    uint64_t Bytes = DL.getTypeStoreSize(LI->getType()).getFixedValue();
                    
                    if (isSafeStaticAccess(Ptr, Bytes, DL)) continue;

                    instrumentAccess(LI, Ptr, Bytes, ShadowBase);
                    VerifiedPtrs.insert(Ptr);
                } else if (auto *SI = dyn_cast<StoreInst>(&I)) {
                    if (isAddrGlobalPtr(SI->getPointerOperand())) continue;

                    Value *Ptr = SI->getPointerOperand();
                    if (VerifiedPtrs.count(Ptr)) continue;
                    if (SafeGEPs.count(Ptr)) continue;

                    uint64_t Bytes = DL.getTypeStoreSize(SI->getValueOperand()->getType()).getFixedValue();

                    if (isSafeStaticAccess(Ptr, Bytes, DL)) continue;

                    instrumentAccess(SI, Ptr, Bytes, ShadowBase);
                    VerifiedPtrs.insert(Ptr);
                }
            }
        }
    }

    void handleCall(CallBase *CB, Value *ShadowBase) {
        Function *CalleeFn = dyn_cast_or_null<Function>(CB->getCalledOperand()->stripPointerCasts());
        if (!CalleeFn) return;

        StringRef Name = CalleeFn->getName();

        if (Name == "malloc") {
            IRBuilder<> IRB(CB);
            Value *SizeArg = CB->getArgOperand(0);
            Value *NewCall = IRB.CreateCall(MyMallocFn, {SizeArg});
            if (NewCall->getType() != CB->getType()) {
                NewCall = IRB.CreateBitCast(NewCall, CB->getType());
            }
            CB->replaceAllUsesWith(NewCall);
            CB->eraseFromParent();
        } 
        else if (Name == "free") {
            IRBuilder<> IRB(CB);
            Value *Arg = CB->getArgOperand(0);
            if (Arg->getType() != PtrTy) Arg = IRB.CreateBitCast(Arg, PtrTy);
            IRB.CreateCall(MyFreeFn, {Arg});
            CB->eraseFromParent();
        }
        else if (Name == "printf") {
            handlePrintf(CB, ShadowBase);
        }
        else if (Name == "scanf" || Name == "__isoc99_scanf") {
            handleScanf(CB, ShadowBase);
        }
    }

    void handlePrintf(CallBase *CB, Value *ShadowBase) {
        if (CB->arg_size() < 1) return;
        Value *Fmt = CB->getArgOperand(0);
        std::string FmtStr;
        if (!getConstCString(Fmt, FmtStr)) return;

        auto [NewFmt, InsertIdxs] = rewritePrintfToDotStarForS(StringRef(FmtStr));
        if (InsertIdxs.empty()) return;

        IRBuilder<> B(CB);
        Value *NewFmtGV = B.CreateGlobalString(NewFmt);

        SmallVector<Value*, 16> NewArgs;
        NewArgs.push_back(NewFmtGV);

        DenseSet<unsigned> NeedPrec;
        for (unsigned k : InsertIdxs) NeedPrec.insert(k);

        unsigned cur = 1;
        for (unsigned i = 1; i < CB->arg_size(); ++i, ++cur) {
            if (NeedPrec.count(cur)) {
                Value *StrArg = CB->getArgOperand(i);
                Value *StrP = B.CreatePointerCast(StrArg, PtrTy);
                Value *MaxLen = ConstantInt::get(I64Ty, (1ULL<<20));
                Value *Len64 = B.CreateCall(StrnSafeFn, {ShadowBase, StrP, MaxLen});
                Value *Len32 = B.CreateTruncOrBitCast(Len64, I32Ty);
                NewArgs.push_back(Len32);
            }
            NewArgs.push_back(CB->getArgOperand(i));
        }
        
        CallInst *NewC = B.CreateCall(CB->getCalledFunction(), NewArgs);
        if (!CB->use_empty()) CB->replaceAllUsesWith(NewC);
        CB->eraseFromParent();
    }

    void handleScanf(CallBase *CB, Value *ShadowBase) {
        if (CB->arg_size() < 1) return;
        Value *Fmt = CB->getArgOperand(0);
        std::string FmtStr;
        bool hasConstFmt = getConstCString(Fmt, FmtStr);
        std::vector<std::pair<unsigned,int>> pairs;
        if (hasConstFmt)
            pairs = getScanfSArgsAndWidths(StringRef(FmtStr));

        bool didAnything = false;
        BasicBlock *BB = CB->getParent();
        auto PostIt = std::next(BasicBlock::iterator(CB));
        IRBuilder<> Post(BB, PostIt);
        const DataLayout &DL = CB->getModule()->getDataLayout();

        if (!pairs.empty()) {
            for (auto [argIdx, width] : pairs) {
                if (1 + argIdx >= CB->arg_size()) break;
                Value *Buf = CB->getArgOperand(1 + argIdx);
                if (!shouldInstrumentPtr(Buf) || !isTrackedPointer(Buf, DL)) continue;
                Value *BP = Post.CreatePointerCast(Buf, PtrTy);
                uint64_t lim = (width > 0) ? (uint64_t)width : (1ULL<<20);
                Value *Max = ConstantInt::get(I64Ty, lim);
                Post.CreateCall(ScanfPostFn, {ShadowBase, BP, Max});
                didAnything = true;
            }
        }
        
        if (!didAnything && hasConstFmt) {
            unsigned sCount = countPercentS(StringRef(FmtStr));
            if (sCount > 0) {
                for (unsigned i = 1; i < CB->arg_size(); ++i) {
                    Type *T = CB->getArgOperand(i)->getType();
                    if (T->isPointerTy() && shouldInstrumentPtr(CB->getArgOperand(i))) {
                        Value *Buf = CB->getArgOperand(i);
                        if (!isTrackedPointer(Buf, DL)) continue;
                        Value *BP = Post.CreatePointerCast(Buf, PtrTy);
                        Value *Max = ConstantInt::get(I64Ty, (1ULL<<20));
                        Post.CreateCall(ScanfPostFn, {ShadowBase, BP, Max});
                    }
                }
            }
        }
    }

    void handleAllocas(const std::vector<AllocaInst*> &UserAllocas, Value *ShadowBase, const DataLayout &DL, Function &F, DenseSet<Instruction*> &SkipInsts) {
        ConstantInt *FFVal = ConstantInt::get(I8Ty, -1, true);
        std::vector<AllocaInst*> AllAllocasForCleanup;

        auto createRedzone = [&](Instruction *InsertBefore, StringRef Name) {
            IRBuilder<> B(InsertBefore);
            AllocaInst *Redzone = B.CreateAlloca(I8Ty, nullptr, Name);
            Redzone->setAlignment(Align(1));
            StoreInst *PoisonStore = B.CreateStore(FFVal, Redzone);
            SkipInsts.insert(PoisonStore);
            
            Value *RZPtr = B.CreatePointerCast(Redzone, PtrTy);
            Value *RZSize = ConstantInt::get(I64Ty, 1);
            B.CreateCall(ClearShadowFn, {ShadowBase, RZPtr, RZSize});
            
            AllAllocasForCleanup.push_back(Redzone);
            return Redzone;
        };

        // Start Redzone
        createRedzone(UserAllocas.front(), "dummy_start");

        for (size_t i = 0; i < UserAllocas.size(); ++i) {
            AllocaInst *AI = UserAllocas[i];
            AllAllocasForCleanup.push_back(AI);

            // Middle Redzone
            if (i + 1 < UserAllocas.size()) {
                createRedzone(UserAllocas[i + 1], "dummy_mid");
            }

            IRBuilder<> B(AI->getNextNode());
            Type *AllocTy = AI->getAllocatedType();
            uint64_t ElemSize = DL.getTypeAllocSize(AllocTy).getFixedValue();
            Value *SizeVal = ConstantInt::get(I64Ty, ElemSize);

            if (AI->isArrayAllocation()) {
                Value *ElemCnt = AI->getArraySize();
                Value *ElemSzV = ConstantInt::get(I64Ty, ElemSize);
                SizeVal = B.CreateMul(ElemSzV, B.CreateZExtOrTrunc(ElemCnt, I64Ty));
            }

            Value *UserPtr = B.CreatePointerCast(AI, PtrTy);
            B.CreateCall(SetShadowFn, {ShadowBase, UserPtr, SizeVal});
        }

        // End Redzone
        createRedzone(UserAllocas.back()->getNextNode(), "dummy_end");

        // Function Exit Cleanup
        for (BasicBlock &BB : F) {
            if (auto *RI = dyn_cast<ReturnInst>(BB.getTerminator())) {
                IRBuilder<> B(RI);
                for (auto *AI : AllAllocasForCleanup) {
                    Type *AllocTy = AI->getAllocatedType();
                    uint64_t ElemSize = DL.getTypeAllocSize(AllocTy).getFixedValue();
                    Value *SizeVal = ConstantInt::get(I64Ty, ElemSize);
                    
                    if (AI->isArrayAllocation()) {
                         Value *ElemCnt = AI->getArraySize();
                         Value *ElemSzV = ConstantInt::get(I64Ty, ElemSize);
                         SizeVal = B.CreateMul(ElemSzV, B.CreateZExtOrTrunc(ElemCnt, I64Ty));
                    }

                    Value *Ptr = B.CreatePointerCast(AI, PtrTy);
                    B.CreateCall(ClearShadowFn, {ShadowBase, Ptr, SizeVal});
                }
            }
        }
    }

    void handleGEP(GetElementPtrInst *G, Value *ShadowBase, const DataLayout &DL) {
        Value *GBasePtr = G->getPointerOperand();
        
        bool isUsedByMemAccess = false;
        for (User *U : G->users()) {
            if (isa<LoadInst>(U) || isa<StoreInst>(U)) {
                if (auto *LI = dyn_cast<LoadInst>(U)) {
                    if (LI->getPointerOperand() == G) isUsedByMemAccess = true;
                } else if (auto *SI = dyn_cast<StoreInst>(U)) {
                    if (SI->getPointerOperand() == G) isUsedByMemAccess = true;
                }
            }
            if (isUsedByMemAccess) break;
        }

        if (isUsedByMemAccess) {
            if (!isTrackedPointer(GBasePtr, G->getModule()->getDataLayout())) return;

            // [Optimization] Static Analysis
            // If the GEP result is statically within the bounds of the base object, we can skip runtime check.
            // We check if accessing 1 byte at the GEP result address is safe.
            if (isSafeStaticAccess(G, 1, DL)) return;

            IRBuilder<> B(G->getNextNode());
            Value *GBaseP = B.CreatePointerCast(GBasePtr, PtrTy);
            Value *GResultP = B.CreatePointerCast(G, PtrTy);
            B.CreateCall(VerifyRangeFn, {ShadowBase, GBaseP, GResultP});
        }
    }

    void handleIntToPtr(IntToPtrInst *ITP, Value *ShadowBase, const DataLayout &DL) {
        Value *IValue = ITP->getOperand(0);
        DenseSet<Value*> Visited;
        Value *GBasePtr = findBasePtr(IValue, DL, Visited);

        if (GBasePtr) {
            IRBuilder<> B(ITP->getNextNode());
            Value *GBaseP = B.CreatePointerCast(GBasePtr, PtrTy);
            Value *GResultP = B.CreatePointerCast(ITP, PtrTy);
            B.CreateCall(VerifyRangeFn, {ShadowBase, GBaseP, GResultP});
        }
    }

    void instrumentAccess(Instruction *I, Value *Ptr, uint64_t Bytes, Value *ShadowBase) {
        if (!isTrackedPointer(Ptr, I->getModule()->getDataLayout())) return;

        IRBuilder<> B(I);
        Value *SizeV = ConstantInt::get(I64Ty, Bytes);
        Value *AddrP = B.CreatePointerCast(Ptr, PtrTy);
        B.CreateCall(VerifyFn, {ShadowBase, AddrP, SizeV});
    }

    bool isAddrGlobalPtr(Value *V) {
        V = V->stripPointerCasts();
        if (auto *GV = dyn_cast<GlobalVariable>(V)) return GV == AddrGV;
        return false;
    }

    bool shouldInstrumentPtr(Value *Ptr) {
        // Check if the underlying object is a global variable
        // We use a simplified check here to avoid version dependency issues with getUnderlyingObject
        // If more complex analysis is needed, we can add it back.
        Value *Obj = Ptr->stripPointerCasts();
        if (isa<GlobalVariable>(Obj)) return false;
        
        // Also check using getUnderlyingObject if possible, but for now this is safer
        // to avoid compilation errors if the signature mismatches.
        return true;
    }

    bool isTrackedPointer(Value *Ptr, const DataLayout &DL) {
        DenseSet<Value *> Visited;
        Value *Base = findBasePtr(Ptr, DL, Visited);

        if (!Base) {
            // errs() << "[DEBUG] isTrackedPointer: Base is null for " << *Ptr << "\n";
            return false;
        }

        if (isa<AllocaInst>(Base)) {
            // errs() << "[DEBUG] isTrackedPointer: Base is Alloca for " << *Ptr << "\n";
            return true;
        }

        if (isa<CallBase>(Base)) {
            return true;
        }

        if (isa<Argument>(Base)) {
            return true;
        }

        // errs() << "[DEBUG] isTrackedPointer: Base is " << *Base << " (Not tracked) for " << *Ptr << "\n";
        return false;
    }
};

} // namespace

extern "C" ::llvm::PassPluginLibraryInfo llvmGetPassPluginInfo() {
    return {
        LLVM_PLUGIN_API_VERSION, "kumpil2r", "v0.1",
        [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &MPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                        if (Name == "kumpil2r") {
                            MPM.addPass(MyPass());
                            return true;
                        }
                        return false;
                    }
            );
        }
    };
}
