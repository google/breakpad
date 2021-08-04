#include "bugsnag_stackwalk_wrapper.h"

#include "common/scoped_ptr.h"
#include "logging.h"
#include "simple_symbol_supplier.h"

#include <string.h>
#include <iomanip>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "google_breakpad/processor/basic_source_line_resolver.h"
#include "google_breakpad/processor/call_stack.h"
#include "google_breakpad/processor/minidump_processor.h"
#include "google_breakpad/processor/process_state.h"
#include "google_breakpad/processor/stack_frame_cpu.h"
#include "processor/pathname_stripper.h"

using google_breakpad::BasicSourceLineResolver;
using google_breakpad::CallStack;
using google_breakpad::HexString;
using google_breakpad::Minidump;
using google_breakpad::MinidumpMemoryList;
using google_breakpad::MinidumpModule;
using google_breakpad::MinidumpModuleList;
using google_breakpad::MinidumpProcessor;
using google_breakpad::MinidumpThreadList;
using google_breakpad::PathnameStripper;
using google_breakpad::ProcessResult;
using google_breakpad::ProcessState;
using google_breakpad::scoped_ptr;
using google_breakpad::SimpleSymbolSupplier;
using google_breakpad::StackFrame;

// Wraps strdup and throws an error if memory allocation fails
char* duplicate(const std::string& s) {
  char* str = strdup(s.c_str());
  if (!str) {
    throw std::bad_alloc();
  }
  return str;
}

// Calls free on passed pointer and sets it to nullptr
void freeAndInvalidate(void** p) {
  free((void*)*p);
  *p = nullptr;
}

void destroyStackframe(void* self) {
  Stackframe* stackframe = (Stackframe*)self;
  if (!stackframe)
    return;

  freeAndInvalidate((void**)&stackframe->filename);
  freeAndInvalidate((void**)&stackframe->method);
  freeAndInvalidate((void**)&stackframe->frameAddress);
  freeAndInvalidate((void**)&stackframe->loadAddress);
  freeAndInvalidate((void**)&stackframe->moduleId);
  freeAndInvalidate((void**)&stackframe->moduleName);
  freeAndInvalidate((void**)&stackframe->returnAddress);
  freeAndInvalidate((void**)&stackframe->symbolAddress);
  freeAndInvalidate((void**)&stackframe->codeFile);
  freeAndInvalidate((void**)&stackframe->trust);
}

void destroyStacktrace(Stacktrace* stacktrace) {
  if (!stacktrace)
    return;

  for (int i = 0; i < stacktrace->frameCount; ++i) {
    destroyStackframe(&stacktrace->frames[i]);
  }
  freeAndInvalidate((void**)&stacktrace->frames);
}

void destroyRegisterData(RegisterData* regData) {
  if (!regData)
    return;

  freeAndInvalidate((void**)&regData->registerName);
  freeAndInvalidate((void**)&regData->registerValue);
}

void destroyRegister(Register* reg) {
  if (!reg)
    return;

  for (int i = 0; i < reg->registerDataCount; ++i) {
    destroyRegisterData(&reg->registerValues[i]);
  }
  freeAndInvalidate((void**)&reg->registerValues);
}

void destroyException(Exception* exception) {
  if (!exception)
    return;

  freeAndInvalidate((void**)&exception->errorClass);
  freeAndInvalidate((void**)&exception->crashAddress);
  destroyStacktrace(&exception->stacktrace);
  destroyRegister(exception->registers);
}

void destroyApp(App* app) {
  if (!app)
    return;

  freeAndInvalidate((void**)&app->binaryArch);
}

void destroyDevice(Device* device) {
  if (!device)
    return;

  freeAndInvalidate((void**)&device->osName);
  freeAndInvalidate((void**)&device->osVersion);
}

void destroyThread(Thread* thread) {
  if (!thread)
    return;

  destroyStacktrace(&thread->stacktrace);
}

void destroyEvent(Event* event) {
  if (!event)
    return;

  destroyApp(&event->app);
  destroyDevice(&event->device);
  destroyException(&event->exception);
  for (int i = 0; i < event->threadCount; ++i) {
    destroyThread(&event->threads[i]);
  }
  freeAndInvalidate((void**)&event->threads);
}

void destroyModuleDetails(ModuleDetails* moduleDetails) {
  if (!moduleDetails)
    return;

  freeAndInvalidate((void**)&moduleDetails->mainModuleId);

  for (int i = 0; i < moduleDetails->moduleCount; i++) {
    freeAndInvalidate((void**)&moduleDetails->moduleIds[i]);
    freeAndInvalidate((void**)&moduleDetails->moduleNames[i]);
  }
  freeAndInvalidate((void**)&moduleDetails->moduleIds);
  freeAndInvalidate((void**)&moduleDetails->moduleNames);
}

void destroyWrappedEvent(WrappedEvent* wrappedEvent) {
  if (!wrappedEvent)
    return;

  freeAndInvalidate((void**)&wrappedEvent->pstrErr);
  destroyEvent(&wrappedEvent->event);
}

void destroyWrappedModuleDetails(WrappedModuleDetails* wrappedModuleDetails) {
  if (!wrappedModuleDetails)
    return;

  freeAndInvalidate((void**)&wrappedModuleDetails->pstrErr);
  destroyModuleDetails(&wrappedModuleDetails->moduleDetails);
}

// Gets the index of the thread that requested a dump be written
int getErrorReportingThreadIndex(const ProcessState& process_state) {
  int index = process_state.requesting_thread();
  // If the dump thread was not available then default to the first available
  // thread
  if (index == -1) {
    index = 0;
  }
  return index;
}

// Gets a friendly version of the stack frame trust value
string getFriendlyTrustValue(StackFrame::FrameTrust stackFrameTrust) {
  switch (stackFrameTrust) {
    case StackFrame::FRAME_TRUST_NONE:
      return "NONE";
    case StackFrame::FRAME_TRUST_SCAN:
      return "SCAN";
    case StackFrame::FRAME_TRUST_CFI_SCAN:
      return "CFI_SCAN";
    case StackFrame::FRAME_TRUST_FP:
      return "FP";
    case StackFrame::FRAME_TRUST_CFI:
      return "CFI";
    case StackFrame::FRAME_TRUST_PREWALKED:
      return "PREWALKED";
    case StackFrame::FRAME_TRUST_CONTEXT:
      return "CONTEXT";
    default:
      return "";
  }
}

// Maps the stacktrace information from a minidump into our Stacktrace struct
static Stacktrace getStack(const CallStack* stack) {
  int frame_count = stack->frames()->size();
  Stackframe* stackframes = new Stackframe[frame_count];
  for (int frame_index = 0; frame_index < frame_count; ++frame_index) {
    const StackFrame* frame = stack->frames()->at(frame_index);
    if (!frame) {
      throw std::runtime_error("Bad frame index");
    }

    string frameAddress = HexString(frame->instruction);
    string method = frame->function_name;
    string loadAddress = "";
    string filename = "";
    string moduleId = "";
    string moduleName = "";
    string returnAddress = HexString(frame->ReturnAddress());
    string symbolAddress = HexString(frame->function_base);
    string codeFile;
    string trust = getFriendlyTrustValue(frame->trust);

    if (symbolAddress == "0x0") {
      symbolAddress = "";
    }

    if (frame->module) {
      loadAddress = HexString(frame->module->base_address());
      filename = frame->module->code_file();
      moduleId = frame->module->debug_identifier();
      moduleName = frame->module->debug_file();
      codeFile = frame->module->code_file();
    }

    Stackframe f = {.filename = duplicate(filename),
                    .method = duplicate(method),
                    .frameAddress = duplicate(frameAddress),
                    .loadAddress = duplicate(loadAddress),
                    .moduleId = duplicate(moduleId),
                    .moduleName = duplicate(moduleName),
                    .returnAddress = duplicate(returnAddress),
                    .symbolAddress = duplicate(symbolAddress),
                    .codeFile = duplicate(codeFile),
                    .trust = duplicate(trust)};
    stackframes[frame_index] = f;
  }

  Stacktrace s = {.frameCount = frame_count, .frames = stackframes};

  return s;
}

// Maps the thread information from a minidump into our Thread struct
Thread* getThreads(const ProcessState& process_state) {
  int thread_count = process_state.threads()->size();
  int error_reporting_thread_index =
      getErrorReportingThreadIndex(process_state);

  Thread* threads = new Thread[thread_count];

  for (int i = 0; i < thread_count; i++) {
    const CallStack* thread = process_state.threads()->at(i);
    int thread_id = thread->tid();
    Thread t = {.id = thread_id,
                .errorReportingThread = (i == error_reporting_thread_index),
                .stacktrace = getStack(thread)};
    threads[i] = t;
  }

  return threads;
}

static string FormatRegisterValue(uint32_t value) {
  std::stringstream ss;
  ss << "0x" << std::hex << std::nouppercase << std::setfill('0')
     << std::setw(8) << value;
  return ss.str();
}

static string FormatRegister64Value(uint64_t value) {
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

static void getRegisterData(std::map<std::string, std::string>& registerMap,
                            const StackFrame* frame,
                            const string& cpu) {
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

static Register* getRegisters(const StackFrame* frame, const string& cpu) {
  // const StackFrame* frame = stack->frames()->at(0);
  // if (!frame) {
  //  throw std::runtime_error("Bad frame index");
  //}
  std::vector<RegisterData> registerDataVector;
  RegisterData* registerDataArray = nullptr;
  Register* registers = nullptr;

  // call function in separate file, pass in frame & cpu, get back map<string,
  // string> of register data
  std::map<std::string, std::string> registerMap;
  getRegisterData(registerMap, frame, cpu);

  if (registerMap.size() > 0) {
    registerDataArray =
        (RegisterData*)malloc(sizeof(RegisterData) * registerMap.size());
    if (!registerDataArray) {
      throw std::bad_alloc();
    }

    uint32_t registerDataIndex = 0;
    for (std::map<std::string, std::string>::const_iterator iterator =
             registerMap.begin();
         iterator != registerMap.end(); ++iterator) {
      RegisterData rd = {.registerName = duplicate(iterator->first.c_str()),
                         .registerValue = duplicate(iterator->second.c_str())};
      registerDataArray[registerDataIndex++] = rd;
    }

    Register r = {.frameIndex = 0,
                  .registerDataCount = static_cast<int>(registerDataIndex),
                  .registerValues = registerDataArray};
    registers = (Register*)malloc(sizeof(Register));
    registers[0] = r;
  }

  return registers;
}

// Maps the information from a minidump into our Event struct
Event getEvent(const ProcessState& process_state) {
  Stacktrace s = getStack(
      process_state.threads()->at(getErrorReportingThreadIndex(process_state)));

  string cpu = process_state.system_info()->cpu;
  const CallStack* stack =
      process_state.threads()->at(getErrorReportingThreadIndex(process_state));
  const StackFrame* frame = stack->frames()->at(0);

  // get the exception register info
  Register* registers = getRegisters(frame, cpu);

  Exception e = {.stacktrace = s,
                 .errorClass = duplicate(process_state.crash_reason())};
  string crashAddress = HexString(process_state.crash_address());
  if (crashAddress != "") {
    e.crashAddress = duplicate(crashAddress);
  }
  e.registerCount = 1;
  e.registers = registers;

  int uptime = 0;
  if (process_state.time_date_stamp() != 0 &&
      process_state.process_create_time() != 0 &&
      process_state.time_date_stamp() >= process_state.process_create_time()) {
    uptime = process_state.time_date_stamp() -
             process_state.process_create_time() * 1000;
  }

  App app = {.duration = uptime,
             .binaryArch = duplicate(process_state.system_info()->cpu)};

  Device device = {
      .osName = duplicate(process_state.system_info()->os.data()),
      .osVersion = duplicate(process_state.system_info()->os_version)};

  int thread_count = process_state.threads()->size();
  Event returnEvent = {.threadCount = thread_count,
                       .exception = e,
                       .app = app,
                       .device = device,
                       .threads = getThreads(process_state)};

  return returnEvent;
}

// Get the details of the modules in a minidump
WrappedModuleDetails GetModuleDetails(const char* minidump_filename) {
  WrappedModuleDetails result = {{0}};

  try {
    Minidump dump(minidump_filename);
    if (!dump.Read()) {
      result.pstrErr = duplicate("failed to read minidump");
      return result;
    }

    MinidumpModuleList* module_list = dump.GetModuleList();
    if (!module_list) {
      result.pstrErr = duplicate("failed to get module list");
      return result;
    }

    result.moduleDetails.moduleCount = module_list->module_count();

    const MinidumpModule* mainModule = module_list->GetMainModule();
    if (!mainModule) {
      throw std::runtime_error("failed to get main module");
    }
    string mainModuleId = mainModule->debug_identifier();
    result.moduleDetails.mainModuleId = duplicate(mainModuleId);

    char** module_ids =
        (char**)malloc(sizeof(char*) * module_list->module_count());
    if (!module_ids) {
      throw std::bad_alloc();
    }
    char** module_names =
        (char**)malloc(sizeof(char*) * module_list->module_count());
    if (!module_names) {
      throw std::bad_alloc();
    }

    for (unsigned int i = 0; i < module_list->module_count(); i++) {
      const MinidumpModule* module = module_list->GetModuleAtIndex(i);
      if (!module) {
        throw std::runtime_error("Bad module index");
      }

      string debug_identifier = module->debug_identifier();
      module_ids[i] = duplicate(debug_identifier);

      string debug_file = PathnameStripper::File(module->debug_file());
      module_names[i] = duplicate(debug_file);
    };
    result.moduleDetails.moduleIds = module_ids;
    result.moduleDetails.moduleNames = module_names;
  } catch (const std::exception& ex) {
    string errMsg = "encountered exception: " + string(ex.what());
    result.pstrErr = duplicate(errMsg);
  } catch (...) {
    result.pstrErr = duplicate("encountered unknown exception");
  }

  return result;
}

// Gets a friendly version of a minidump processing failure reason
string getFriendlyFailureReason(ProcessResult process_result) {
  switch (process_result) {
    case google_breakpad::PROCESS_ERROR_MINIDUMP_NOT_FOUND:
      return "minidump not found";
    case google_breakpad::PROCESS_ERROR_NO_MINIDUMP_HEADER:
      return "no minidump header";
    case google_breakpad::PROCESS_ERROR_NO_THREAD_LIST:
      return "no thread list";
    case google_breakpad::PROCESS_ERROR_GETTING_THREAD:
      return "error getting thread";
    case google_breakpad::PROCESS_ERROR_GETTING_THREAD_ID:
      return "error getting thread ID";
    case google_breakpad::PROCESS_ERROR_DUPLICATE_REQUESTING_THREADS:
      return "more than one requesting thread";
    case google_breakpad::PROCESS_SYMBOL_SUPPLIER_INTERRUPTED:
      return "dump processing interrupted by symbol supplier";
    default:
      return "unknown failure reason";
  }
}

// Gets an Event payload from the minidump.
// Note: Logic for parsing the minidump is based on PrintMinidumpProcess in
// minidump_stackwalk.cc
WrappedEvent GetEventFromMinidump(const char* filename,
                                  const int symbol_path_count,
                                  const char** symbol_paths) {
  WrappedEvent result = {{0}};

  try {
    // Apply a symbol supplier if we've been given one or more symbol paths (to
    // allow the stack data to be used when walking the stacktrace)
    std::vector<string> supplied_symbol_paths;
    scoped_ptr<SimpleSymbolSupplier> symbol_supplier;
    for (int i = 0; i < symbol_path_count; i++) {
      supplied_symbol_paths.push_back(symbol_paths[i]);
    }
    if (!supplied_symbol_paths.empty()) {
      symbol_supplier.reset(new SimpleSymbolSupplier(supplied_symbol_paths));
    }

    BasicSourceLineResolver resolver;
    MinidumpProcessor minidump_processor(symbol_supplier.get(), &resolver);

    // Increase the maximum number of threads and regions.
    MinidumpThreadList::set_max_threads(std::numeric_limits<uint32_t>::max());
    MinidumpMemoryList::set_max_regions(std::numeric_limits<uint32_t>::max());

    // Process the minidump.
    Minidump dump(filename);
    if (!dump.Read()) {
      result.pstrErr = strdup("failed to read minidump");
      return result;
    }

    ProcessState process_state;
    ProcessResult process_result =
        minidump_processor.Process(&dump, &process_state);
    if (process_result != google_breakpad::PROCESS_OK) {
      string errMsg = "failed to process minidump: " +
                      getFriendlyFailureReason(process_result);
      result.pstrErr = duplicate(errMsg);
      return result;
    }

    // Map the process state to an Event struct
    result.event = getEvent(process_state);
  } catch (const std::exception& ex) {
    string errMsg = "encountered exception: " + string(ex.what());
    result.pstrErr = duplicate(errMsg);
  } catch (...) {
    result.pstrErr = duplicate("encountered unknown exception");
  }

  return result;
}

// Frees the memory allocated by an Event
void DestroyEvent(WrappedEvent* wrapped_event) {
  if (wrapped_event) {
    destroyWrappedEvent(wrapped_event);
  }
}

// Frees the memory allocated by the module details
void DestroyModuleDetails(WrappedModuleDetails* wrapped_module_details) {
  if (wrapped_module_details) {
    destroyWrappedModuleDetails(wrapped_module_details);
  }
}
