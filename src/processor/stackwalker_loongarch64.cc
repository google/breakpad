// Copyright (c) 2013 Google Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//     * Neither the name of Google Inc. nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// stackwalker_loongarch64.cc: LOONGARCH64-specific stackwalker.
//
// See stackwalker_loongarch64.h for documentation.

#include "common/scoped_ptr.h"
#include "google_breakpad/processor/call_stack.h"
#include "google_breakpad/processor/code_modules.h"
#include "google_breakpad/processor/memory_region.h"
#include "google_breakpad/processor/source_line_resolver_interface.h"
#include "google_breakpad/processor/stack_frame_cpu.h"
#include "processor/cfi_frame_info.h"
#include "processor/logging.h"
#include "processor/postfix_evaluator-inl.h"
#include "processor/stackwalker_loongarch64.h"
#include "processor/windows_frame_info.h"
#include "google_breakpad/common/minidump_cpu_loongarch64.h"

namespace google_breakpad {

StackwalkerLOONGARCH64::StackwalkerLOONGARCH64(const SystemInfo* system_info,
                                 const MDRawContextLOONGARCH64* context,
                                 MemoryRegion* memory,
                                 const CodeModules* modules,
                                 StackFrameSymbolizer* resolver_helper)
: Stackwalker(system_info, memory, modules, resolver_helper),
  context_(context) {
  if (memory_) {
    if (0xffffffffffffffff - memory_->GetBase() < memory_->GetSize() - 1) {
      BPLOG(ERROR) << "Memory out of range for stackwalking loongarch64: "
          << HexString(memory_->GetBase())
          << "+"
          << HexString(memory_->GetSize());
      memory_ = NULL;
    }
  }
}

StackFrame* StackwalkerLOONGARCH64::GetContextFrame() {
  if (!context_) {
    BPLOG(ERROR) << "Can't get context frame without context.";
    return NULL;
  }

  StackFrameLOONGARCH64* frame = new StackFrameLOONGARCH64();

  // The instruction pointer is stored directly in a register, so pull it
  // straight out of the CPU context structure.
  frame->context = *context_;
  frame->context_validity = StackFrameLOONGARCH64::CONTEXT_VALID_ALL;
  frame->trust = StackFrame::FRAME_TRUST_CONTEXT;
  frame->instruction = frame->context.csr_epc;

  return frame;
}

// Register names for loongarch.
static const char* const kRegisterNames[] = {
    "$zero", "$ra",  "$tp",  "$sp",  "$a0",  "$a1",  "$a2",  "$a3",
    "$a4",   "$a5",  "$a6",  "$a7",  "$t0",  "$t1",  "$t2",  "$t3",
    "$t4",   "$t5",  "$t6",  "$t7",  "$t8",  "$x",   "$fp",  "$s0",
    "$s1",   "$s2",  "$s3",  "$s4",  "$s5",  "$s6",  "$s7",  "$s8",
    "$fa0",  "$fa1", "$fa2", "$fa3", "$fa4", "$fa5", "$fa6", "$fa7",
    "$ft0",  "$ft1", "$ft2", "$ft3", "$ft4", "$ft5", "$ft6", "$ft7",
    "$ft8",  "$ft9", "$ft10","$ft11","$ft12","$ft13","$ft14","$ft15",
    "$fs0",  "$fs1", "$fs2", "$fs3", "$fs4", "$fs5", "$fs6",  "$fs7",
    NULL
  // TODO(gordanac): add float point save registers
};

StackFrameLOONGARCH64* StackwalkerLOONGARCH64::GetCallerByCFIFrameInfo(
    const vector<StackFrame*>& frames,
    CFIFrameInfo* cfi_frame_info) {
  StackFrameLOONGARCH64* last_frame = static_cast<StackFrameLOONGARCH64*>(frames.back());

  uint64_t pc = 0;

  // Populate a dictionary with the valid register values in last_frame.
  CFIFrameInfo::RegisterValueMap<uint64_t> callee_registers;
  // Use the STACK CFI data to recover the caller's register values.
  CFIFrameInfo::RegisterValueMap<uint64_t> caller_registers;

  for (int i = 0; kRegisterNames[i]; ++i) {
    caller_registers[kRegisterNames[i]] = last_frame->context.iregs[i];
    callee_registers[kRegisterNames[i]] = last_frame->context.iregs[i];
  }

  if (!cfi_frame_info->FindCallerRegs(callee_registers, *memory_,
      &caller_registers))  {
    return NULL;
  }

  CFIFrameInfo::RegisterValueMap<uint64_t>::const_iterator entry =
      caller_registers.find(".cfa");

  if (entry != caller_registers.end()) {
    caller_registers["$sp"] = entry->second;
  }

  entry = caller_registers.find(".ra");
  if (entry != caller_registers.end()) {
    caller_registers["$ra"] = entry->second;
    pc = entry->second - sizeof(pc);
  }
  caller_registers["$pc"] = pc;
  // Construct a new stack frame given the values the CFI recovered.
  scoped_ptr<StackFrameLOONGARCH64> frame(new StackFrameLOONGARCH64());

  for (int i = 0; kRegisterNames[i]; ++i) {
    CFIFrameInfo::RegisterValueMap<uint64_t>::const_iterator caller_entry =
        caller_registers.find(kRegisterNames[i]);

    if (caller_entry != caller_registers.end()) {
      // The value of this register is recovered; fill the context with the
      // value from caller_registers.
      frame->context.iregs[i] = caller_entry->second;
      frame->context_validity |= StackFrameLOONGARCH64::RegisterValidFlag(i);
    } else {
      // If the STACK CFI data doesn't mention some callee-save register, and
      // it is valid in the callee, assume the callee has not yet changed it.
      // Calee-save registers according to the loongarch psABI specification are:
      // $s0 to $s8, $fp, $sp
      frame->context.iregs[i] = last_frame->context.iregs[i];
      frame->context_validity |= StackFrameLOONGARCH64::CONTEXT_VALID_S0;
      frame->context_validity |= StackFrameLOONGARCH64::CONTEXT_VALID_S1;
      frame->context_validity |= StackFrameLOONGARCH64::CONTEXT_VALID_S2;
      frame->context_validity |= StackFrameLOONGARCH64::CONTEXT_VALID_S3;
      frame->context_validity |= StackFrameLOONGARCH64::CONTEXT_VALID_S4;
      frame->context_validity |= StackFrameLOONGARCH64::CONTEXT_VALID_S5;
      frame->context_validity |= StackFrameLOONGARCH64::CONTEXT_VALID_S6;
      frame->context_validity |= StackFrameLOONGARCH64::CONTEXT_VALID_S7;
      frame->context_validity |= StackFrameLOONGARCH64::CONTEXT_VALID_S8;
      frame->context_validity |= StackFrameLOONGARCH64::CONTEXT_VALID_FP;
      frame->context_validity |= StackFrameLOONGARCH64::CONTEXT_VALID_SP;
    }
  }

  frame->context.csr_epc = caller_registers["$pc"];
  frame->instruction = caller_registers["$pc"];
  frame->context_validity |= StackFrameLOONGARCH64::CONTEXT_VALID_PC;

  frame->context.iregs[MD_CONTEXT_LOONGARCH64_REG_RA] = caller_registers["$ra"];
  frame->context_validity |= StackFrameLOONGARCH64::CONTEXT_VALID_RA;

  frame->trust = StackFrame::FRAME_TRUST_CFI;

  return frame.release();
}

StackFrame* StackwalkerLOONGARCH64::GetCallerFrame(const CallStack* stack,
                                            bool stack_scan_allowed) {
  if (!memory_ || !stack) {
    BPLOG(ERROR) << "Can't get caller frame without memory or stack";
    return NULL;
  }

  const vector<StackFrame*>& frames = *stack->frames();
  StackFrameLOONGARCH64* last_frame = static_cast<StackFrameLOONGARCH64*>(frames.back());
  scoped_ptr<StackFrameLOONGARCH64> new_frame;

  // See if there is DWARF call frame information covering this address.
  scoped_ptr<CFIFrameInfo> cfi_frame_info(
    frame_symbolizer_->FindCFIFrameInfo(last_frame));
  if (cfi_frame_info.get())
    new_frame.reset(GetCallerByCFIFrameInfo(frames, cfi_frame_info.get()));

  // If caller frame is not found in CFI try analyzing the stack.
  if (stack_scan_allowed && !new_frame.get()) {
    new_frame.reset(GetCallerByStackScan(frames));
  }

  // If nothing worked, tell the caller.
  if (!new_frame.get()) {
    return NULL;
  }

  // Should we terminate the stack walk? (end-of-stack or broken invariant)
  if (TerminateWalk(new_frame->context.csr_epc,
                    new_frame->context.iregs[MD_CONTEXT_LOONGARCH64_REG_SP],
                    last_frame->context.iregs[MD_CONTEXT_LOONGARCH64_REG_SP],
                    frames.size() == 1)) {
    return NULL;
  }

  return new_frame.release();
}

StackFrameLOONGARCH64* StackwalkerLOONGARCH64::GetCallerByStackScan(
    const vector<StackFrame*>& frames) {
  const uint32_t kMaxFrameStackSize = 1024;

  StackFrameLOONGARCH64* last_frame = static_cast<StackFrameLOONGARCH64*>(frames.back());

  uint64_t last_sp = last_frame->context.iregs[MD_CONTEXT_LOONGARCH64_REG_SP];
  uint64_t caller_pc, caller_sp, caller_fp;

  // Return address cannot be obtained directly.
  // Force stackwalking.

  // We cannot use frame pointer to get the return address.
  // We'll scan the stack for a
  // return address. This can happen if last_frame is executing code
  // for a module for which we don't have symbols.
  int count = kMaxFrameStackSize / sizeof(caller_pc);

  do {
    // Scanning for return address from stack pointer of the last frame.
    if (!ScanForReturnAddress(last_sp, &caller_sp, &caller_pc, count)) {
      // If we can't find an instruction pointer even with stack scanning,
      // give up.
      BPLOG(ERROR) << " ScanForReturnAddress failed ";
      return NULL;
    }
    // Get $fp stored in the stack frame.
    if (!memory_->GetMemoryAtAddress(caller_sp - sizeof(caller_pc),
        &caller_fp)) {
      BPLOG(INFO) << " GetMemoryAtAddress for fp failed " ;
      return NULL;
    }

    count = count - (caller_sp - last_sp) / sizeof(caller_pc);
    // Now scan the next address in the stack.
    last_sp = caller_sp + sizeof(caller_pc);
  } while ((caller_fp - caller_sp >= kMaxFrameStackSize) && count > 0);

  if (!count) {
    BPLOG(INFO) << " No frame found " ;
    return NULL;
  }

  // ScanForReturnAddress found a reasonable return address. Advance
  // $sp to the location above the one where the return address was
  // found.
  caller_sp += sizeof(caller_pc);
  // caller_pc is actually containing $ra value;
  // $pc is two instructions before $ra,
  // so the caller_pc needs to be decremented accordingly.
  caller_pc -= sizeof(caller_pc);

  // Create a new stack frame (ownership will be transferred to the caller)
  // and fill it in.
  StackFrameLOONGARCH64* frame = new StackFrameLOONGARCH64();
  frame->trust = StackFrame::FRAME_TRUST_SCAN;
  frame->context = last_frame->context;
  frame->context.csr_epc = caller_pc;
  frame->context_validity |= StackFrameLOONGARCH64::CONTEXT_VALID_PC;
  frame->instruction = caller_pc;

  frame->context.iregs[MD_CONTEXT_LOONGARCH64_REG_SP] = caller_sp;
  frame->context_validity |= StackFrameLOONGARCH64::CONTEXT_VALID_SP;
  frame->context.iregs[MD_CONTEXT_LOONGARCH64_REG_FP] = caller_fp;
  frame->context_validity |= StackFrameLOONGARCH64::CONTEXT_VALID_FP;

  frame->context.iregs[MD_CONTEXT_LOONGARCH64_REG_RA] =
      caller_pc + sizeof(caller_pc);
  frame->context_validity |= StackFrameLOONGARCH64::CONTEXT_VALID_RA;

  return frame;
}

}  // namespace google_breakpad

