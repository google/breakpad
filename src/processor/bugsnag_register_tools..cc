#include <string.h>
#include <iomanip>
//#include <limits>
#include <sstream>
//#include <stdexcept>
#include <string>
#include <vector>
#include <map>

#include "google_breakpad/processor/stack_frame_cpu.h"

using google_breakpad::StackFrame;

namespace bugsnag_breakpad {

static std::string XXXFormatRegisterValue(uint32_t value) {
  std::stringstream ss;
  ss << "0x" << std::hex << std::nouppercase << std::setfill('0')
     << std::setw(8) << value;
  return ss.str();
}

static std::string XXXFormatRegister64Value(uint64_t value) {
  std::stringstream ss;
  ss << "0x" << std::hex << std::nouppercase << std::setfill('0')
     << std::setw(16) << value;
  return ss.str();
}

static void XXXAddToRegisterMap(std::map<std::string, std::string>& registerMap,
                             const char* name,
                             const std::string value) {
  registerMap.insert(std::make_pair(name, value));
}

static void XXXgetRegisterData(std::map<std::string, std::string>& registerMap,
                            const StackFrame* frame,
                            const std::string& cpu) {
  if (cpu == "x86") {
    using google_breakpad::StackFrameX86;
    const StackFrameX86* frame_x86 =
        reinterpret_cast<const StackFrameX86*>(frame);

    if (frame_x86->context_validity & StackFrameX86::CONTEXT_VALID_EIP) {
      XXXAddToRegisterMap(registerMap, "eip",
                       XXXFormatRegisterValue(frame_x86->context.eip));
    }
    if (frame_x86->context_validity & StackFrameX86::CONTEXT_VALID_ESP) {
      XXXAddToRegisterMap(registerMap, "esp",
                       XXXFormatRegisterValue(frame_x86->context.esp));
    }
    if (frame_x86->context_validity & StackFrameX86::CONTEXT_VALID_EBP) {
      XXXAddToRegisterMap(registerMap, "ebp",
                       XXXFormatRegisterValue(frame_x86->context.ebp));
    }
    if (frame_x86->context_validity & StackFrameX86::CONTEXT_VALID_EBX) {
      XXXAddToRegisterMap(registerMap, "ebx",
                       XXXFormatRegisterValue(frame_x86->context.ebx));
    }
    if (frame_x86->context_validity & StackFrameX86::CONTEXT_VALID_ESI) {
      XXXAddToRegisterMap(registerMap, "esi",
                       XXXFormatRegisterValue(frame_x86->context.esi));
    }
    if (frame_x86->context_validity & StackFrameX86::CONTEXT_VALID_EDI) {
      XXXAddToRegisterMap(registerMap, "edi",
                       XXXFormatRegisterValue(frame_x86->context.edi));
    }
    if (frame_x86->context_validity == StackFrameX86::CONTEXT_VALID_ALL) {
      XXXAddToRegisterMap(registerMap, "eax",
                       XXXFormatRegisterValue(frame_x86->context.eax));
      XXXAddToRegisterMap(registerMap, "ecx",
                       XXXFormatRegisterValue(frame_x86->context.ecx));
      XXXAddToRegisterMap(registerMap, "edx",
                       XXXFormatRegisterValue(frame_x86->context.edx));
      XXXAddToRegisterMap(registerMap, "efl",
                       XXXFormatRegisterValue(frame_x86->context.eflags));
    }
  } else if (cpu == "ppc") {
    using google_breakpad::StackFramePPC;
    const StackFramePPC* frame_ppc =
        reinterpret_cast<const StackFramePPC*>(frame);

    if (frame_ppc->context_validity & StackFramePPC::CONTEXT_VALID_SRR0) {
      XXXAddToRegisterMap(registerMap, "srr0",
                       XXXFormatRegisterValue(frame_ppc->context.srr0));
    }
    if (frame_ppc->context_validity & StackFramePPC::CONTEXT_VALID_GPR1) {
      XXXAddToRegisterMap(registerMap, "r1",
                       XXXFormatRegisterValue(frame_ppc->context.gpr[1]));
    }
  } else if (cpu == "amd64") {
    using google_breakpad::StackFrameAMD64;
    const StackFrameAMD64* frame_amd64 =
        reinterpret_cast<const StackFrameAMD64*>(frame);

    if (frame_amd64->context_validity & StackFrameAMD64::CONTEXT_VALID_RAX) {
      XXXAddToRegisterMap(registerMap, "rax",
                       XXXFormatRegister64Value(frame_amd64->context.rax));
    }
    if (frame_amd64->context_validity & StackFrameAMD64::CONTEXT_VALID_RDX) {
      XXXAddToRegisterMap(registerMap, "rdx",
                       XXXFormatRegister64Value(frame_amd64->context.rdx));
    }
    if (frame_amd64->context_validity & StackFrameAMD64::CONTEXT_VALID_RCX) {
      XXXAddToRegisterMap(registerMap, "rcx",
                       XXXFormatRegister64Value(frame_amd64->context.rcx));
    }
    if (frame_amd64->context_validity & StackFrameAMD64::CONTEXT_VALID_RBX) {
      XXXAddToRegisterMap(registerMap, "rbx",
                       XXXFormatRegister64Value(frame_amd64->context.rbx));
    }
    if (frame_amd64->context_validity & StackFrameAMD64::CONTEXT_VALID_RSI) {
      XXXAddToRegisterMap(registerMap, "rsi",
                       XXXFormatRegister64Value(frame_amd64->context.rsi));
    }
    if (frame_amd64->context_validity & StackFrameAMD64::CONTEXT_VALID_RDI) {
      XXXAddToRegisterMap(registerMap, "rdi",
                       XXXFormatRegister64Value(frame_amd64->context.rdi));
    }
    if (frame_amd64->context_validity & StackFrameAMD64::CONTEXT_VALID_RBP) {
      XXXAddToRegisterMap(registerMap, "rbp",
                       XXXFormatRegister64Value(frame_amd64->context.rbp));
    }
    if (frame_amd64->context_validity & StackFrameAMD64::CONTEXT_VALID_RSP) {
      XXXAddToRegisterMap(registerMap, "rsp",
                       XXXFormatRegister64Value(frame_amd64->context.rsp));
    }
    if (frame_amd64->context_validity & StackFrameAMD64::CONTEXT_VALID_R8) {
      XXXAddToRegisterMap(registerMap, "r8",
                       XXXFormatRegister64Value(frame_amd64->context.r8));
    }
    if (frame_amd64->context_validity & StackFrameAMD64::CONTEXT_VALID_R9) {
      XXXAddToRegisterMap(registerMap, "r9",
                       XXXFormatRegister64Value(frame_amd64->context.r9));
    }
    if (frame_amd64->context_validity & StackFrameAMD64::CONTEXT_VALID_R10) {
      XXXAddToRegisterMap(registerMap, "r10",
                       XXXFormatRegister64Value(frame_amd64->context.r10));
    }
    if (frame_amd64->context_validity & StackFrameAMD64::CONTEXT_VALID_R11) {
      XXXAddToRegisterMap(registerMap, "r11",
                       XXXFormatRegister64Value(frame_amd64->context.r11));
    }
    if (frame_amd64->context_validity & StackFrameAMD64::CONTEXT_VALID_R12) {
      XXXAddToRegisterMap(registerMap, "r12",
                       XXXFormatRegister64Value(frame_amd64->context.r12));
    }
    if (frame_amd64->context_validity & StackFrameAMD64::CONTEXT_VALID_R13) {
      XXXAddToRegisterMap(registerMap, "r13",
                       XXXFormatRegister64Value(frame_amd64->context.r13));
    }
    if (frame_amd64->context_validity & StackFrameAMD64::CONTEXT_VALID_R14) {
      XXXAddToRegisterMap(registerMap, "r14",
                       XXXFormatRegister64Value(frame_amd64->context.r14));
    }
    if (frame_amd64->context_validity & StackFrameAMD64::CONTEXT_VALID_R15) {
      XXXAddToRegisterMap(registerMap, "r15",
                       XXXFormatRegister64Value(frame_amd64->context.r15));
    }
    if (frame_amd64->context_validity & StackFrameAMD64::CONTEXT_VALID_RIP) {
      XXXAddToRegisterMap(registerMap, "rip",
                       XXXFormatRegister64Value(frame_amd64->context.rip));
    }
  } else if (cpu == "sparc") {
    using google_breakpad::StackFrameSPARC;
    const StackFrameSPARC* frame_sparc =
        reinterpret_cast<const StackFrameSPARC*>(frame);

    if (frame_sparc->context_validity & StackFrameSPARC::CONTEXT_VALID_SP) {
      XXXAddToRegisterMap(registerMap, "sp",
                       XXXFormatRegisterValue(frame_sparc->context.g_r[14]));
    }
    if (frame_sparc->context_validity & StackFrameSPARC::CONTEXT_VALID_FP) {
      XXXAddToRegisterMap(registerMap, "fp",
                       XXXFormatRegisterValue(frame_sparc->context.g_r[30]));
    }
    if (frame_sparc->context_validity & StackFrameSPARC::CONTEXT_VALID_PC) {
      XXXAddToRegisterMap(registerMap, "pc",
                       XXXFormatRegisterValue(frame_sparc->context.pc));
    }
  } else if (cpu == "arm") {
    using google_breakpad::StackFrameARM;
    const StackFrameARM* frame_arm =
        reinterpret_cast<const StackFrameARM*>(frame);

    // Argument registers (caller-saves), which will likely only be valid
    // for the youngest frame.
    if (frame_arm->context_validity & StackFrameARM::CONTEXT_VALID_R0) {
      XXXAddToRegisterMap(registerMap, "r0",
                       XXXFormatRegisterValue(frame_arm->context.iregs[0]));
    }
    if (frame_arm->context_validity & StackFrameARM::CONTEXT_VALID_R1) {
      XXXAddToRegisterMap(registerMap, "r1",
                       XXXFormatRegisterValue(frame_arm->context.iregs[1]));
    }
    if (frame_arm->context_validity & StackFrameARM::CONTEXT_VALID_R2) {
      XXXAddToRegisterMap(registerMap, "r2",
                       XXXFormatRegisterValue(frame_arm->context.iregs[2]));
    }
    if (frame_arm->context_validity & StackFrameARM::CONTEXT_VALID_R3) {
      XXXAddToRegisterMap(registerMap, "r3",
                       XXXFormatRegisterValue(frame_arm->context.iregs[3]));
    }

    // General-purpose callee-saves registers.
    if (frame_arm->context_validity & StackFrameARM::CONTEXT_VALID_R4) {
      XXXAddToRegisterMap(registerMap, "r4",
                       XXXFormatRegisterValue(frame_arm->context.iregs[4]));
    }
    if (frame_arm->context_validity & StackFrameARM::CONTEXT_VALID_R5) {
      XXXAddToRegisterMap(registerMap, "r5",
                       XXXFormatRegisterValue(frame_arm->context.iregs[5]));
    }
    if (frame_arm->context_validity & StackFrameARM::CONTEXT_VALID_R6) {
      XXXAddToRegisterMap(registerMap, "r6",
                       XXXFormatRegisterValue(frame_arm->context.iregs[6]));
    }
    if (frame_arm->context_validity & StackFrameARM::CONTEXT_VALID_R7) {
      XXXAddToRegisterMap(registerMap, "r7",
                       XXXFormatRegisterValue(frame_arm->context.iregs[7]));
    }
    if (frame_arm->context_validity & StackFrameARM::CONTEXT_VALID_R8) {
      XXXAddToRegisterMap(registerMap, "r8",
                       XXXFormatRegisterValue(frame_arm->context.iregs[8]));
    }
    if (frame_arm->context_validity & StackFrameARM::CONTEXT_VALID_R9) {
      XXXAddToRegisterMap(registerMap, "r9",
                       XXXFormatRegisterValue(frame_arm->context.iregs[9]));
    }
    if (frame_arm->context_validity & StackFrameARM::CONTEXT_VALID_R10) {
      XXXAddToRegisterMap(registerMap, "r10",
                       XXXFormatRegisterValue(frame_arm->context.iregs[10]));
    }
    if (frame_arm->context_validity & StackFrameARM::CONTEXT_VALID_R12) {
      XXXAddToRegisterMap(registerMap, "r12",
                       XXXFormatRegisterValue(frame_arm->context.iregs[12]));
    }

    // Registers with a dedicated or conventional purpose.
    if (frame_arm->context_validity & StackFrameARM::CONTEXT_VALID_FP) {
      XXXAddToRegisterMap(registerMap, "fp",
                       XXXFormatRegisterValue(frame_arm->context.iregs[11]));
    }
    if (frame_arm->context_validity & StackFrameARM::CONTEXT_VALID_SP) {
      XXXAddToRegisterMap(registerMap, "sp",
                       XXXFormatRegisterValue(frame_arm->context.iregs[13]));
    }
    if (frame_arm->context_validity & StackFrameARM::CONTEXT_VALID_LR) {
      XXXAddToRegisterMap(registerMap, "lr",
                       XXXFormatRegisterValue(frame_arm->context.iregs[14]));
    }
    if (frame_arm->context_validity & StackFrameARM::CONTEXT_VALID_PC) {
      XXXAddToRegisterMap(registerMap, "pc",
                       XXXFormatRegisterValue(frame_arm->context.iregs[15]));
    }
  } else if (cpu == "arm64") {
    using google_breakpad::StackFrameARM64;
    const StackFrameARM64* frame_arm64 =
        reinterpret_cast<const StackFrameARM64*>(frame);

    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X0) {
      XXXAddToRegisterMap(registerMap, "x0",
                       XXXFormatRegister64Value(frame_arm64->context.iregs[0]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X1) {
      XXXAddToRegisterMap(registerMap, "x1",
                       XXXFormatRegister64Value(frame_arm64->context.iregs[1]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X2) {
      XXXAddToRegisterMap(registerMap, "x2",
                       XXXFormatRegister64Value(frame_arm64->context.iregs[2]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X3) {
      XXXAddToRegisterMap(registerMap, "x3",
                       XXXFormatRegister64Value(frame_arm64->context.iregs[3]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X4) {
      XXXAddToRegisterMap(registerMap, "x4",
                       XXXFormatRegister64Value(frame_arm64->context.iregs[4]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X5) {
      XXXAddToRegisterMap(registerMap, "x5",
                       XXXFormatRegister64Value(frame_arm64->context.iregs[5]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X6) {
      XXXAddToRegisterMap(registerMap, "x6",
                       XXXFormatRegister64Value(frame_arm64->context.iregs[6]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X7) {
      XXXAddToRegisterMap(registerMap, "x7",
                       XXXFormatRegister64Value(frame_arm64->context.iregs[7]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X8) {
      XXXAddToRegisterMap(registerMap, "x8",
                       XXXFormatRegister64Value(frame_arm64->context.iregs[8]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X9) {
      XXXAddToRegisterMap(registerMap, "x9",
                       XXXFormatRegister64Value(frame_arm64->context.iregs[9]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X10) {
      XXXAddToRegisterMap(registerMap, "x10",
                       XXXFormatRegister64Value(frame_arm64->context.iregs[10]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X11) {
      XXXAddToRegisterMap(registerMap, "x11",
                       XXXFormatRegister64Value(frame_arm64->context.iregs[11]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X12) {
      XXXAddToRegisterMap(registerMap, "x12",
                       XXXFormatRegister64Value(frame_arm64->context.iregs[12]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X13) {
      XXXAddToRegisterMap(registerMap, "x13",
                       XXXFormatRegister64Value(frame_arm64->context.iregs[13]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X14) {
      XXXAddToRegisterMap(registerMap, "x14",
                       XXXFormatRegister64Value(frame_arm64->context.iregs[14]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X15) {
      XXXAddToRegisterMap(registerMap, "x15",
                       XXXFormatRegister64Value(frame_arm64->context.iregs[15]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X16) {
      XXXAddToRegisterMap(registerMap, "x16",
                       XXXFormatRegister64Value(frame_arm64->context.iregs[16]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X17) {
      XXXAddToRegisterMap(registerMap, "x17",
                       XXXFormatRegister64Value(frame_arm64->context.iregs[17]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X18) {
      XXXAddToRegisterMap(registerMap, "x18",
                       XXXFormatRegister64Value(frame_arm64->context.iregs[18]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X19) {
      XXXAddToRegisterMap(registerMap, "x19",
                       XXXFormatRegister64Value(frame_arm64->context.iregs[19]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X20) {
      XXXAddToRegisterMap(registerMap, "x20",
                       XXXFormatRegister64Value(frame_arm64->context.iregs[20]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X21) {
      XXXAddToRegisterMap(registerMap, "x21",
                       XXXFormatRegister64Value(frame_arm64->context.iregs[21]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X22) {
      XXXAddToRegisterMap(registerMap, "x22",
                       XXXFormatRegister64Value(frame_arm64->context.iregs[22]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X23) {
      XXXAddToRegisterMap(registerMap, "x23",
                       XXXFormatRegister64Value(frame_arm64->context.iregs[23]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X24) {
      XXXAddToRegisterMap(registerMap, "x24",
                       XXXFormatRegister64Value(frame_arm64->context.iregs[24]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X25) {
      XXXAddToRegisterMap(registerMap, "x25",
                       XXXFormatRegister64Value(frame_arm64->context.iregs[25]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X26) {
      XXXAddToRegisterMap(registerMap, "x26",
                       XXXFormatRegister64Value(frame_arm64->context.iregs[26]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X27) {
      XXXAddToRegisterMap(registerMap, "x27",
                       XXXFormatRegister64Value(frame_arm64->context.iregs[27]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X28) {
      XXXAddToRegisterMap(registerMap, "x28",
                       XXXFormatRegister64Value(frame_arm64->context.iregs[28]));
    }

    // Registers with a dedicated or conventional purpose.
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_FP) {
      XXXAddToRegisterMap(registerMap, "fp",
                       XXXFormatRegister64Value(frame_arm64->context.iregs[29]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_LR) {
      XXXAddToRegisterMap(registerMap, "lr",
                       XXXFormatRegister64Value(frame_arm64->context.iregs[30]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_SP) {
      XXXAddToRegisterMap(registerMap, "sp",
                       XXXFormatRegister64Value(frame_arm64->context.iregs[31]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_PC) {
      XXXAddToRegisterMap(registerMap, "pc",
                       XXXFormatRegister64Value(frame_arm64->context.iregs[32]));
    }
  } else if ((cpu == "mips") || (cpu == "mips64")) {
    using google_breakpad::StackFrameMIPS;
    const StackFrameMIPS* frame_mips =
        reinterpret_cast<const StackFrameMIPS*>(frame);

    if (frame_mips->context_validity & StackFrameMIPS::CONTEXT_VALID_GP) {
      XXXAddToRegisterMap(registerMap, "gp",
                       XXXFormatRegister64Value(
                           frame_mips->context.iregs[MD_CONTEXT_MIPS_REG_GP]));
    }
    if (frame_mips->context_validity & StackFrameMIPS::CONTEXT_VALID_SP) {
      XXXAddToRegisterMap(registerMap, "sp",
                       XXXFormatRegister64Value(
                           frame_mips->context.iregs[MD_CONTEXT_MIPS_REG_SP]));
    }
    if (frame_mips->context_validity & StackFrameMIPS::CONTEXT_VALID_FP) {
      XXXAddToRegisterMap(registerMap, "fp",
                       XXXFormatRegister64Value(
                           frame_mips->context.iregs[MD_CONTEXT_MIPS_REG_FP]));
    }
    if (frame_mips->context_validity & StackFrameMIPS::CONTEXT_VALID_RA) {
      XXXAddToRegisterMap(registerMap, "ra",
                       XXXFormatRegister64Value(
                           frame_mips->context.iregs[MD_CONTEXT_MIPS_REG_RA]));
    }
    if (frame_mips->context_validity & StackFrameMIPS::CONTEXT_VALID_PC) {
      XXXAddToRegisterMap(registerMap, "pc",
                       XXXFormatRegister64Value(frame_mips->context.epc));
    }

    // Save registers s0-s7
    if (frame_mips->context_validity & StackFrameMIPS::CONTEXT_VALID_S0) {
      XXXAddToRegisterMap(registerMap, "s0",
                       XXXFormatRegister64Value(
                           frame_mips->context.iregs[MD_CONTEXT_MIPS_REG_S0]));
    }
    if (frame_mips->context_validity & StackFrameMIPS::CONTEXT_VALID_S1) {
      XXXAddToRegisterMap(registerMap, "s1",
                       XXXFormatRegister64Value(
                           frame_mips->context.iregs[MD_CONTEXT_MIPS_REG_S1]));
    }
    if (frame_mips->context_validity & StackFrameMIPS::CONTEXT_VALID_S2) {
      XXXAddToRegisterMap(registerMap, "s2",
                       XXXFormatRegister64Value(
                           frame_mips->context.iregs[MD_CONTEXT_MIPS_REG_S2]));
    }
    if (frame_mips->context_validity & StackFrameMIPS::CONTEXT_VALID_S3) {
      XXXAddToRegisterMap(registerMap, "s3",
                       XXXFormatRegister64Value(
                           frame_mips->context.iregs[MD_CONTEXT_MIPS_REG_S3]));
    }
    if (frame_mips->context_validity & StackFrameMIPS::CONTEXT_VALID_S4) {
      XXXAddToRegisterMap(registerMap, "s4",
                       XXXFormatRegister64Value(
                           frame_mips->context.iregs[MD_CONTEXT_MIPS_REG_S4]));
    }
    if (frame_mips->context_validity & StackFrameMIPS::CONTEXT_VALID_S5) {
      XXXAddToRegisterMap(registerMap, "s5",
                       XXXFormatRegister64Value(
                           frame_mips->context.iregs[MD_CONTEXT_MIPS_REG_S5]));
    }
    if (frame_mips->context_validity & StackFrameMIPS::CONTEXT_VALID_S6) {
      XXXAddToRegisterMap(registerMap, "s6",
                       XXXFormatRegister64Value(
                           frame_mips->context.iregs[MD_CONTEXT_MIPS_REG_S6]));
    }
    if (frame_mips->context_validity & StackFrameMIPS::CONTEXT_VALID_S7) {
      XXXAddToRegisterMap(registerMap, "s7",
                       XXXFormatRegister64Value(
                           frame_mips->context.iregs[MD_CONTEXT_MIPS_REG_S7]));
    }
  }
}

} // namespace bugsnag_breakpad