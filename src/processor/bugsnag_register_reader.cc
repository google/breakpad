#include "bugsnag_register_reader.h"

#include <string.h>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include <map>

#include "google_breakpad/processor/stack_frame_cpu.h"

using google_breakpad::StackFrame;

namespace bugsnag_breakpad {

static std::string FormatRegisterValue(uint32_t value) {
  std::stringstream ss;
  ss << "0x" << std::hex << std::nouppercase << std::setfill('0')
     << std::setw(8) << value;
  return ss.str();
}

static std::string FormatRegister64Value(uint64_t value) {
  std::stringstream ss;
  ss << "0x" << std::hex << std::nouppercase << std::setfill('0')
     << std::setw(16) << value;
  return ss.str();
}

static void AddToRegisterMap(std::map<std::string, std::string>& registerMap,
                             const char* name,
                             const std::string value) {
  registerMap.insert(std::make_pair(name, value));
}

void getRegisterData(std::map<std::string, std::string>& registerMap,
                            const StackFrame* frame,
                            const std::string& cpu) {
  if (cpu == "x86") {
    using google_breakpad::StackFrameX86;
    const StackFrameX86* frame_x86 =
        reinterpret_cast<const StackFrameX86*>(frame);

    if (frame_x86->context_validity & StackFrameX86::CONTEXT_VALID_EIP) {
      AddToRegisterMap(registerMap, "eip",
                       FormatRegisterValue(frame_x86->context.eip));
    }
    if (frame_x86->context_validity & StackFrameX86::CONTEXT_VALID_ESP) {
      AddToRegisterMap(registerMap, "esp",
                       FormatRegisterValue(frame_x86->context.esp));
    }
    if (frame_x86->context_validity & StackFrameX86::CONTEXT_VALID_EBP) {
      AddToRegisterMap(registerMap, "ebp",
                       FormatRegisterValue(frame_x86->context.ebp));
    }
    if (frame_x86->context_validity & StackFrameX86::CONTEXT_VALID_EBX) {
      AddToRegisterMap(registerMap, "ebx",
                       FormatRegisterValue(frame_x86->context.ebx));
    }
    if (frame_x86->context_validity & StackFrameX86::CONTEXT_VALID_ESI) {
      AddToRegisterMap(registerMap, "esi",
                       FormatRegisterValue(frame_x86->context.esi));
    }
    if (frame_x86->context_validity & StackFrameX86::CONTEXT_VALID_EDI) {
      AddToRegisterMap(registerMap, "edi",
                       FormatRegisterValue(frame_x86->context.edi));
    }
    if (frame_x86->context_validity == StackFrameX86::CONTEXT_VALID_ALL) {
      AddToRegisterMap(registerMap, "eax",
                       FormatRegisterValue(frame_x86->context.eax));
      AddToRegisterMap(registerMap, "ecx",
                       FormatRegisterValue(frame_x86->context.ecx));
      AddToRegisterMap(registerMap, "edx",
                       FormatRegisterValue(frame_x86->context.edx));
      AddToRegisterMap(registerMap, "efl",
                       FormatRegisterValue(frame_x86->context.eflags));
    }
  } else if (cpu == "ppc") {
    using google_breakpad::StackFramePPC;
    const StackFramePPC* frame_ppc =
        reinterpret_cast<const StackFramePPC*>(frame);

    if (frame_ppc->context_validity & StackFramePPC::CONTEXT_VALID_SRR0) {
      AddToRegisterMap(registerMap, "srr0",
                       FormatRegisterValue(frame_ppc->context.srr0));
    }
    if (frame_ppc->context_validity & StackFramePPC::CONTEXT_VALID_GPR1) {
      AddToRegisterMap(registerMap, "r1",
                       FormatRegisterValue(frame_ppc->context.gpr[1]));
    }
  } else if (cpu == "amd64") {
    using google_breakpad::StackFrameAMD64;
    const StackFrameAMD64* frame_amd64 =
        reinterpret_cast<const StackFrameAMD64*>(frame);

    if (frame_amd64->context_validity & StackFrameAMD64::CONTEXT_VALID_RAX) {
      AddToRegisterMap(registerMap, "rax",
                       FormatRegister64Value(frame_amd64->context.rax));
    }
    if (frame_amd64->context_validity & StackFrameAMD64::CONTEXT_VALID_RDX) {
      AddToRegisterMap(registerMap, "rdx",
                       FormatRegister64Value(frame_amd64->context.rdx));
    }
    if (frame_amd64->context_validity & StackFrameAMD64::CONTEXT_VALID_RCX) {
      AddToRegisterMap(registerMap, "rcx",
                       FormatRegister64Value(frame_amd64->context.rcx));
    }
    if (frame_amd64->context_validity & StackFrameAMD64::CONTEXT_VALID_RBX) {
      AddToRegisterMap(registerMap, "rbx",
                       FormatRegister64Value(frame_amd64->context.rbx));
    }
    if (frame_amd64->context_validity & StackFrameAMD64::CONTEXT_VALID_RSI) {
      AddToRegisterMap(registerMap, "rsi",
                       FormatRegister64Value(frame_amd64->context.rsi));
    }
    if (frame_amd64->context_validity & StackFrameAMD64::CONTEXT_VALID_RDI) {
      AddToRegisterMap(registerMap, "rdi",
                       FormatRegister64Value(frame_amd64->context.rdi));
    }
    if (frame_amd64->context_validity & StackFrameAMD64::CONTEXT_VALID_RBP) {
      AddToRegisterMap(registerMap, "rbp",
                       FormatRegister64Value(frame_amd64->context.rbp));
    }
    if (frame_amd64->context_validity & StackFrameAMD64::CONTEXT_VALID_RSP) {
      AddToRegisterMap(registerMap, "rsp",
                       FormatRegister64Value(frame_amd64->context.rsp));
    }
    if (frame_amd64->context_validity & StackFrameAMD64::CONTEXT_VALID_R8) {
      AddToRegisterMap(registerMap, "r8",
                       FormatRegister64Value(frame_amd64->context.r8));
    }
    if (frame_amd64->context_validity & StackFrameAMD64::CONTEXT_VALID_R9) {
      AddToRegisterMap(registerMap, "r9",
                       FormatRegister64Value(frame_amd64->context.r9));
    }
    if (frame_amd64->context_validity & StackFrameAMD64::CONTEXT_VALID_R10) {
      AddToRegisterMap(registerMap, "r10",
                       FormatRegister64Value(frame_amd64->context.r10));
    }
    if (frame_amd64->context_validity & StackFrameAMD64::CONTEXT_VALID_R11) {
      AddToRegisterMap(registerMap, "r11",
                       FormatRegister64Value(frame_amd64->context.r11));
    }
    if (frame_amd64->context_validity & StackFrameAMD64::CONTEXT_VALID_R12) {
      AddToRegisterMap(registerMap, "r12",
                       FormatRegister64Value(frame_amd64->context.r12));
    }
    if (frame_amd64->context_validity & StackFrameAMD64::CONTEXT_VALID_R13) {
      AddToRegisterMap(registerMap, "r13",
                       FormatRegister64Value(frame_amd64->context.r13));
    }
    if (frame_amd64->context_validity & StackFrameAMD64::CONTEXT_VALID_R14) {
      AddToRegisterMap(registerMap, "r14",
                       FormatRegister64Value(frame_amd64->context.r14));
    }
    if (frame_amd64->context_validity & StackFrameAMD64::CONTEXT_VALID_R15) {
      AddToRegisterMap(registerMap, "r15",
                       FormatRegister64Value(frame_amd64->context.r15));
    }
    if (frame_amd64->context_validity & StackFrameAMD64::CONTEXT_VALID_RIP) {
      AddToRegisterMap(registerMap, "rip",
                       FormatRegister64Value(frame_amd64->context.rip));
    }
  } else if (cpu == "sparc") {
    using google_breakpad::StackFrameSPARC;
    const StackFrameSPARC* frame_sparc =
        reinterpret_cast<const StackFrameSPARC*>(frame);

    if (frame_sparc->context_validity & StackFrameSPARC::CONTEXT_VALID_SP) {
      AddToRegisterMap(registerMap, "sp",
                       FormatRegisterValue(frame_sparc->context.g_r[14]));
    }
    if (frame_sparc->context_validity & StackFrameSPARC::CONTEXT_VALID_FP) {
      AddToRegisterMap(registerMap, "fp",
                       FormatRegisterValue(frame_sparc->context.g_r[30]));
    }
    if (frame_sparc->context_validity & StackFrameSPARC::CONTEXT_VALID_PC) {
      AddToRegisterMap(registerMap, "pc",
                       FormatRegisterValue(frame_sparc->context.pc));
    }
  } else if (cpu == "arm") {
    using google_breakpad::StackFrameARM;
    const StackFrameARM* frame_arm =
        reinterpret_cast<const StackFrameARM*>(frame);

    // Argument registers (caller-saves), which will likely only be valid
    // for the youngest frame.
    if (frame_arm->context_validity & StackFrameARM::CONTEXT_VALID_R0) {
      AddToRegisterMap(registerMap, "r0",
                       FormatRegisterValue(frame_arm->context.iregs[0]));
    }
    if (frame_arm->context_validity & StackFrameARM::CONTEXT_VALID_R1) {
      AddToRegisterMap(registerMap, "r1",
                       FormatRegisterValue(frame_arm->context.iregs[1]));
    }
    if (frame_arm->context_validity & StackFrameARM::CONTEXT_VALID_R2) {
      AddToRegisterMap(registerMap, "r2",
                       FormatRegisterValue(frame_arm->context.iregs[2]));
    }
    if (frame_arm->context_validity & StackFrameARM::CONTEXT_VALID_R3) {
      AddToRegisterMap(registerMap, "r3",
                       FormatRegisterValue(frame_arm->context.iregs[3]));
    }

    // General-purpose callee-saves registers.
    if (frame_arm->context_validity & StackFrameARM::CONTEXT_VALID_R4) {
      AddToRegisterMap(registerMap, "r4",
                       FormatRegisterValue(frame_arm->context.iregs[4]));
    }
    if (frame_arm->context_validity & StackFrameARM::CONTEXT_VALID_R5) {
      AddToRegisterMap(registerMap, "r5",
                       FormatRegisterValue(frame_arm->context.iregs[5]));
    }
    if (frame_arm->context_validity & StackFrameARM::CONTEXT_VALID_R6) {
      AddToRegisterMap(registerMap, "r6",
                       FormatRegisterValue(frame_arm->context.iregs[6]));
    }
    if (frame_arm->context_validity & StackFrameARM::CONTEXT_VALID_R7) {
      AddToRegisterMap(registerMap, "r7",
                       FormatRegisterValue(frame_arm->context.iregs[7]));
    }
    if (frame_arm->context_validity & StackFrameARM::CONTEXT_VALID_R8) {
      AddToRegisterMap(registerMap, "r8",
                       FormatRegisterValue(frame_arm->context.iregs[8]));
    }
    if (frame_arm->context_validity & StackFrameARM::CONTEXT_VALID_R9) {
      AddToRegisterMap(registerMap, "r9",
                       FormatRegisterValue(frame_arm->context.iregs[9]));
    }
    if (frame_arm->context_validity & StackFrameARM::CONTEXT_VALID_R10) {
      AddToRegisterMap(registerMap, "r10",
                       FormatRegisterValue(frame_arm->context.iregs[10]));
    }
    if (frame_arm->context_validity & StackFrameARM::CONTEXT_VALID_R12) {
      AddToRegisterMap(registerMap, "r12",
                       FormatRegisterValue(frame_arm->context.iregs[12]));
    }

    // Registers with a dedicated or conventional purpose.
    if (frame_arm->context_validity & StackFrameARM::CONTEXT_VALID_FP) {
      AddToRegisterMap(registerMap, "fp",
                       FormatRegisterValue(frame_arm->context.iregs[11]));
    }
    if (frame_arm->context_validity & StackFrameARM::CONTEXT_VALID_SP) {
      AddToRegisterMap(registerMap, "sp",
                       FormatRegisterValue(frame_arm->context.iregs[13]));
    }
    if (frame_arm->context_validity & StackFrameARM::CONTEXT_VALID_LR) {
      AddToRegisterMap(registerMap, "lr",
                       FormatRegisterValue(frame_arm->context.iregs[14]));
    }
    if (frame_arm->context_validity & StackFrameARM::CONTEXT_VALID_PC) {
      AddToRegisterMap(registerMap, "pc",
                       FormatRegisterValue(frame_arm->context.iregs[15]));
    }
  } else if (cpu == "arm64") {
    using google_breakpad::StackFrameARM64;
    const StackFrameARM64* frame_arm64 =
        reinterpret_cast<const StackFrameARM64*>(frame);

    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X0) {
      AddToRegisterMap(registerMap, "x0",
                       FormatRegister64Value(frame_arm64->context.iregs[0]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X1) {
      AddToRegisterMap(registerMap, "x1",
                       FormatRegister64Value(frame_arm64->context.iregs[1]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X2) {
      AddToRegisterMap(registerMap, "x2",
                       FormatRegister64Value(frame_arm64->context.iregs[2]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X3) {
      AddToRegisterMap(registerMap, "x3",
                       FormatRegister64Value(frame_arm64->context.iregs[3]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X4) {
      AddToRegisterMap(registerMap, "x4",
                       FormatRegister64Value(frame_arm64->context.iregs[4]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X5) {
      AddToRegisterMap(registerMap, "x5",
                       FormatRegister64Value(frame_arm64->context.iregs[5]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X6) {
      AddToRegisterMap(registerMap, "x6",
                       FormatRegister64Value(frame_arm64->context.iregs[6]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X7) {
      AddToRegisterMap(registerMap, "x7",
                       FormatRegister64Value(frame_arm64->context.iregs[7]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X8) {
      AddToRegisterMap(registerMap, "x8",
                       FormatRegister64Value(frame_arm64->context.iregs[8]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X9) {
      AddToRegisterMap(registerMap, "x9",
                       FormatRegister64Value(frame_arm64->context.iregs[9]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X10) {
      AddToRegisterMap(registerMap, "x10",
                       FormatRegister64Value(frame_arm64->context.iregs[10]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X11) {
      AddToRegisterMap(registerMap, "x11",
                       FormatRegister64Value(frame_arm64->context.iregs[11]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X12) {
      AddToRegisterMap(registerMap, "x12",
                       FormatRegister64Value(frame_arm64->context.iregs[12]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X13) {
      AddToRegisterMap(registerMap, "x13",
                       FormatRegister64Value(frame_arm64->context.iregs[13]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X14) {
      AddToRegisterMap(registerMap, "x14",
                       FormatRegister64Value(frame_arm64->context.iregs[14]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X15) {
      AddToRegisterMap(registerMap, "x15",
                       FormatRegister64Value(frame_arm64->context.iregs[15]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X16) {
      AddToRegisterMap(registerMap, "x16",
                       FormatRegister64Value(frame_arm64->context.iregs[16]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X17) {
      AddToRegisterMap(registerMap, "x17",
                       FormatRegister64Value(frame_arm64->context.iregs[17]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X18) {
      AddToRegisterMap(registerMap, "x18",
                       FormatRegister64Value(frame_arm64->context.iregs[18]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X19) {
      AddToRegisterMap(registerMap, "x19",
                       FormatRegister64Value(frame_arm64->context.iregs[19]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X20) {
      AddToRegisterMap(registerMap, "x20",
                       FormatRegister64Value(frame_arm64->context.iregs[20]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X21) {
      AddToRegisterMap(registerMap, "x21",
                       FormatRegister64Value(frame_arm64->context.iregs[21]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X22) {
      AddToRegisterMap(registerMap, "x22",
                       FormatRegister64Value(frame_arm64->context.iregs[22]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X23) {
      AddToRegisterMap(registerMap, "x23",
                       FormatRegister64Value(frame_arm64->context.iregs[23]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X24) {
      AddToRegisterMap(registerMap, "x24",
                       FormatRegister64Value(frame_arm64->context.iregs[24]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X25) {
      AddToRegisterMap(registerMap, "x25",
                       FormatRegister64Value(frame_arm64->context.iregs[25]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X26) {
      AddToRegisterMap(registerMap, "x26",
                       FormatRegister64Value(frame_arm64->context.iregs[26]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X27) {
      AddToRegisterMap(registerMap, "x27",
                       FormatRegister64Value(frame_arm64->context.iregs[27]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X28) {
      AddToRegisterMap(registerMap, "x28",
                       FormatRegister64Value(frame_arm64->context.iregs[28]));
    }

    // Registers with a dedicated or conventional purpose.
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_FP) {
      AddToRegisterMap(registerMap, "fp",
                       FormatRegister64Value(frame_arm64->context.iregs[29]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_LR) {
      AddToRegisterMap(registerMap, "lr",
                       FormatRegister64Value(frame_arm64->context.iregs[30]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_SP) {
      AddToRegisterMap(registerMap, "sp",
                       FormatRegister64Value(frame_arm64->context.iregs[31]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_PC) {
      AddToRegisterMap(registerMap, "pc",
                       FormatRegister64Value(frame_arm64->context.iregs[32]));
    }
  } else if ((cpu == "mips") || (cpu == "mips64")) {
    using google_breakpad::StackFrameMIPS;
    const StackFrameMIPS* frame_mips =
        reinterpret_cast<const StackFrameMIPS*>(frame);

    if (frame_mips->context_validity & StackFrameMIPS::CONTEXT_VALID_GP) {
      AddToRegisterMap(registerMap, "gp",
                       FormatRegister64Value(
                           frame_mips->context.iregs[MD_CONTEXT_MIPS_REG_GP]));
    }
    if (frame_mips->context_validity & StackFrameMIPS::CONTEXT_VALID_SP) {
      AddToRegisterMap(registerMap, "sp",
                       FormatRegister64Value(
                           frame_mips->context.iregs[MD_CONTEXT_MIPS_REG_SP]));
    }
    if (frame_mips->context_validity & StackFrameMIPS::CONTEXT_VALID_FP) {
      AddToRegisterMap(registerMap, "fp",
                       FormatRegister64Value(
                           frame_mips->context.iregs[MD_CONTEXT_MIPS_REG_FP]));
    }
    if (frame_mips->context_validity & StackFrameMIPS::CONTEXT_VALID_RA) {
      AddToRegisterMap(registerMap, "ra",
                       FormatRegister64Value(
                           frame_mips->context.iregs[MD_CONTEXT_MIPS_REG_RA]));
    }
    if (frame_mips->context_validity & StackFrameMIPS::CONTEXT_VALID_PC) {
      AddToRegisterMap(registerMap, "pc",
                       FormatRegister64Value(frame_mips->context.epc));
    }

    // Save registers s0-s7
    if (frame_mips->context_validity & StackFrameMIPS::CONTEXT_VALID_S0) {
      AddToRegisterMap(registerMap, "s0",
                       FormatRegister64Value(
                           frame_mips->context.iregs[MD_CONTEXT_MIPS_REG_S0]));
    }
    if (frame_mips->context_validity & StackFrameMIPS::CONTEXT_VALID_S1) {
      AddToRegisterMap(registerMap, "s1",
                       FormatRegister64Value(
                           frame_mips->context.iregs[MD_CONTEXT_MIPS_REG_S1]));
    }
    if (frame_mips->context_validity & StackFrameMIPS::CONTEXT_VALID_S2) {
      AddToRegisterMap(registerMap, "s2",
                       FormatRegister64Value(
                           frame_mips->context.iregs[MD_CONTEXT_MIPS_REG_S2]));
    }
    if (frame_mips->context_validity & StackFrameMIPS::CONTEXT_VALID_S3) {
      AddToRegisterMap(registerMap, "s3",
                       FormatRegister64Value(
                           frame_mips->context.iregs[MD_CONTEXT_MIPS_REG_S3]));
    }
    if (frame_mips->context_validity & StackFrameMIPS::CONTEXT_VALID_S4) {
      AddToRegisterMap(registerMap, "s4",
                       FormatRegister64Value(
                           frame_mips->context.iregs[MD_CONTEXT_MIPS_REG_S4]));
    }
    if (frame_mips->context_validity & StackFrameMIPS::CONTEXT_VALID_S5) {
      AddToRegisterMap(registerMap, "s5",
                       FormatRegister64Value(
                           frame_mips->context.iregs[MD_CONTEXT_MIPS_REG_S5]));
    }
    if (frame_mips->context_validity & StackFrameMIPS::CONTEXT_VALID_S6) {
      AddToRegisterMap(registerMap, "s6",
                       FormatRegister64Value(
                           frame_mips->context.iregs[MD_CONTEXT_MIPS_REG_S6]));
    }
    if (frame_mips->context_validity & StackFrameMIPS::CONTEXT_VALID_S7) {
      AddToRegisterMap(registerMap, "s7",
                       FormatRegister64Value(
                           frame_mips->context.iregs[MD_CONTEXT_MIPS_REG_S7]));
    }
  }
}

} // namespace bugsnag_breakpad
