#include "bugsnag_stackwalk_wrapper.h"

#include "common/scoped_ptr.h"
#include "logging.h"
#include "simple_symbol_supplier.h"

#include <string.h>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>

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
  ss << "0x" << std::hex << std::nouppercase << std::setfill('0') << std::setw(8) << value;
  return ss.str();
}

static string FormatRegister64Value(uint64_t value) {
  std::stringstream ss;
  ss << "0x" << std::hex << std::nouppercase << std::setfill('0') << std::setw(16) << value;
  return ss.str();
}

static void AddToRegisterMap(std::map<std::string, std::string>& registerMap, const char* name, const std::string value) {
  //registerMap.insert(std::make_pair("esp", FormatRegisterValue(frame_x86->context.esp)));
  registerMap.insert(std::make_pair(name, value));
}

static void getRegisterData(std::map<std::string, std::string>& registerMap, const StackFrame* frame, const string& cpu) {
  //int sequence = 0;
  if (cpu == "x86") {
    using google_breakpad::StackFrameX86;
    const StackFrameX86* frame_x86 =
      reinterpret_cast<const StackFrameX86*>(frame);

    if (frame_x86->context_validity & StackFrameX86::CONTEXT_VALID_EIP)
      //sequence = PrintRegister("eip", frame_x86->context.eip, sequence);
      AddToRegisterMap(registerMap, "eip", FormatRegisterValue(frame_x86->context.eip));

      //const string regValue = FormatRegisterValue(frame_x86->context.eip);
      //const string regName = "eip";
      //registerMap.insert(std::make_pair(regName, regValue));
      //RegisterData rd = {.registerName = regName.c_str(), .registerValue = regValue.c_str()};
      //if (rd.registerName == rd.registerValue) {
        // TODO
      //}
      //registerMap.insert(std::make_pair("eip", FormatRegisterValue(frame_x86->context.eip)));
      //registerDataVector.push_back(rd);
    if (frame_x86->context_validity & StackFrameX86::CONTEXT_VALID_ESP)
      //sequence = PrintRegister("esp", frame_x86->context.esp, sequence);
      AddToRegisterMap(registerMap, "esp", FormatRegisterValue(frame_x86->context.esp));
    if (frame_x86->context_validity & StackFrameX86::CONTEXT_VALID_EBP)
      //sequence = PrintRegister("ebp", frame_x86->context.ebp, sequence);
      AddToRegisterMap(registerMap, "ebp", FormatRegisterValue(frame_x86->context.ebp));
    if (frame_x86->context_validity & StackFrameX86::CONTEXT_VALID_EBX)
      //sequence = PrintRegister("ebx", frame_x86->context.ebx, sequence);
      AddToRegisterMap(registerMap, "ebx", FormatRegisterValue(frame_x86->context.ebx));
    if (frame_x86->context_validity & StackFrameX86::CONTEXT_VALID_ESI)
      //sequence = PrintRegister("esi", frame_x86->context.esi, sequence);
      AddToRegisterMap(registerMap, "esi", FormatRegisterValue(frame_x86->context.esi));
    if (frame_x86->context_validity & StackFrameX86::CONTEXT_VALID_EDI)
      //sequence = PrintRegister("edi", frame_x86->context.edi, sequence);
      AddToRegisterMap(registerMap, "edi", FormatRegisterValue(frame_x86->context.edi));
    if (frame_x86->context_validity == StackFrameX86::CONTEXT_VALID_ALL) {
      //sequence = PrintRegister("eax", frame_x86->context.eax, sequence);
      //sequence = PrintRegister("ecx", frame_x86->context.ecx, sequence);
      //sequence = PrintRegister("edx", frame_x86->context.edx, sequence);
      //sequence = PrintRegister("efl", frame_x86->context.eflags, sequence)
      AddToRegisterMap(registerMap, "eax", FormatRegisterValue(frame_x86->context.eax));
      AddToRegisterMap(registerMap, "ecx", FormatRegisterValue(frame_x86->context.ecx));
      AddToRegisterMap(registerMap, "edx", FormatRegisterValue(frame_x86->context.edx));
      AddToRegisterMap(registerMap, "efl", FormatRegisterValue(frame_x86->context.eflags));
    }
  } else if (cpu == "ppc") {
    using google_breakpad::StackFramePPC;
    const StackFramePPC* frame_ppc =
      reinterpret_cast<const StackFramePPC*>(frame);

    if (frame_ppc->context_validity & StackFramePPC::CONTEXT_VALID_SRR0)
      //sequence = PrintRegister("srr0", frame_ppc->context.srr0, sequence);
      AddToRegisterMap(registerMap, "srr0", FormatRegisterValue(frame_ppc->context.srr0));
    if (frame_ppc->context_validity & StackFramePPC::CONTEXT_VALID_GPR1)
      //sequence = PrintRegister("r1", frame_ppc->context.gpr[1], sequence);
      AddToRegisterMap(registerMap, "r1", FormatRegisterValue(frame_ppc->context.gpr[1]));
  } else if (cpu == "amd64") {
    using google_breakpad::StackFrameAMD64;
    const StackFrameAMD64* frame_amd64 =
      reinterpret_cast<const StackFrameAMD64*>(frame);

    if (frame_amd64->context_validity & StackFrameAMD64::CONTEXT_VALID_RAX)
      //sequence = PrintRegister64("rax", frame_amd64->context.rax, sequence);
      AddToRegisterMap(registerMap, "rax", FormatRegister64Value(frame_amd64->context.rax));
    if (frame_amd64->context_validity & StackFrameAMD64::CONTEXT_VALID_RDX)
      //sequence = PrintRegister64("rdx", frame_amd64->context.rdx, sequence);
      AddToRegisterMap(registerMap, "rdx", FormatRegister64Value(frame_amd64->context.rdx));
    if (frame_amd64->context_validity & StackFrameAMD64::CONTEXT_VALID_RCX)
      //sequence = PrintRegister64("rcx", frame_amd64->context.rcx, sequence);
      AddToRegisterMap(registerMap, "rcx", FormatRegister64Value(frame_amd64->context.rcx));
    if (frame_amd64->context_validity & StackFrameAMD64::CONTEXT_VALID_RBX)
      //sequence = PrintRegister64("rbx", frame_amd64->context.rbx, sequence);
      AddToRegisterMap(registerMap, "rbx", FormatRegister64Value(frame_amd64->context.rbx));
    if (frame_amd64->context_validity & StackFrameAMD64::CONTEXT_VALID_RSI)
      //sequence = PrintRegister64("rsi", frame_amd64->context.rsi, sequence);
      AddToRegisterMap(registerMap, "rsi", FormatRegister64Value(frame_amd64->context.rsi));
    if (frame_amd64->context_validity & StackFrameAMD64::CONTEXT_VALID_RDI)
      //sequence = PrintRegister64("rdi", frame_amd64->context.rdi, sequence);
      AddToRegisterMap(registerMap, "rdi", FormatRegister64Value(frame_amd64->context.rdi));
    if (frame_amd64->context_validity & StackFrameAMD64::CONTEXT_VALID_RBP)
      //sequence = PrintRegister64("rbp", frame_amd64->context.rbp, sequence);
      AddToRegisterMap(registerMap, "rbp", FormatRegister64Value(frame_amd64->context.rbp));
    if (frame_amd64->context_validity & StackFrameAMD64::CONTEXT_VALID_RSP)
      //sequence = PrintRegister64("rsp", frame_amd64->context.rsp, sequence);
      AddToRegisterMap(registerMap, "rsp", FormatRegister64Value(frame_amd64->context.rsp));
    if (frame_amd64->context_validity & StackFrameAMD64::CONTEXT_VALID_R8)
      //sequence = PrintRegister64("r8", frame_amd64->context.r8, sequence);
      AddToRegisterMap(registerMap, "r8", FormatRegister64Value(frame_amd64->context.r8));
    if (frame_amd64->context_validity & StackFrameAMD64::CONTEXT_VALID_R9)
      //sequence = PrintRegister64("r9", frame_amd64->context.r9, sequence);
      AddToRegisterMap(registerMap, "r9", FormatRegister64Value(frame_amd64->context.r9));
    if (frame_amd64->context_validity & StackFrameAMD64::CONTEXT_VALID_R10)
      //sequence = PrintRegister64("r10", frame_amd64->context.r10, sequence);
      AddToRegisterMap(registerMap, "r10", FormatRegister64Value(frame_amd64->context.r10));
    if (frame_amd64->context_validity & StackFrameAMD64::CONTEXT_VALID_R11)
      //sequence = PrintRegister64("r11", frame_amd64->context.r11, sequence);
      AddToRegisterMap(registerMap, "r11", FormatRegister64Value(frame_amd64->context.r11));
    if (frame_amd64->context_validity & StackFrameAMD64::CONTEXT_VALID_R12)
      //sequence = PrintRegister64("r12", frame_amd64->context.r12, sequence);
      AddToRegisterMap(registerMap, "r12", FormatRegister64Value(frame_amd64->context.r12));
    if (frame_amd64->context_validity & StackFrameAMD64::CONTEXT_VALID_R13)
      //sequence = PrintRegister64("r13", frame_amd64->context.r13, sequence);
      AddToRegisterMap(registerMap, "r13", FormatRegister64Value(frame_amd64->context.r13));
    if (frame_amd64->context_validity & StackFrameAMD64::CONTEXT_VALID_R14)
      //sequence = PrintRegister64("r14", frame_amd64->context.r14, sequence);
      AddToRegisterMap(registerMap, "r14", FormatRegister64Value(frame_amd64->context.r14));
    if (frame_amd64->context_validity & StackFrameAMD64::CONTEXT_VALID_R15)
      //sequence = PrintRegister64("r15", frame_amd64->context.r15, sequence);
      AddToRegisterMap(registerMap, "r15", FormatRegister64Value(frame_amd64->context.r15));
    if (frame_amd64->context_validity & StackFrameAMD64::CONTEXT_VALID_RIP)
      //sequence = PrintRegister64("rip", frame_amd64->context.rip, sequence);
      AddToRegisterMap(registerMap, "rip", FormatRegister64Value(frame_amd64->context.rip));
  } else if (cpu == "sparc") {
    using google_breakpad::StackFrameSPARC;
    const StackFrameSPARC* frame_sparc =
      reinterpret_cast<const StackFrameSPARC*>(frame);

    if (frame_sparc->context_validity & StackFrameSPARC::CONTEXT_VALID_SP)
      //sequence = PrintRegister("sp", frame_sparc->context.g_r[14], sequence);
      AddToRegisterMap(registerMap, "sp", FormatRegisterValue(frame_sparc->context.g_r[14]));
    if (frame_sparc->context_validity & StackFrameSPARC::CONTEXT_VALID_FP)
      //sequence = PrintRegister("fp", frame_sparc->context.g_r[30], sequence);
      AddToRegisterMap(registerMap, "fp", FormatRegisterValue(frame_sparc->context.g_r[30]));
    if (frame_sparc->context_validity & StackFrameSPARC::CONTEXT_VALID_PC)
      //sequence = PrintRegister("pc", frame_sparc->context.pc, sequence);
      AddToRegisterMap(registerMap, "pc", FormatRegisterValue(frame_sparc->context.pc));
  } else if (cpu == "arm") {
    using google_breakpad::StackFrameARM;
    const StackFrameARM* frame_arm =
      reinterpret_cast<const StackFrameARM*>(frame);

    // Argument registers (caller-saves), which will likely only be valid
    // for the youngest frame.
    if (frame_arm->context_validity & StackFrameARM::CONTEXT_VALID_R0)
      //sequence = PrintRegister("r0", frame_arm->context.iregs[0], sequence);
      AddToRegisterMap(registerMap, "r0", FormatRegisterValue(frame_arm->context.iregs[0]));
    if (frame_arm->context_validity & StackFrameARM::CONTEXT_VALID_R1)
      //sequence = PrintRegister("r1", frame_arm->context.iregs[1], sequence);
      AddToRegisterMap(registerMap, "r1", FormatRegisterValue(frame_arm->context.iregs[1]));
    if (frame_arm->context_validity & StackFrameARM::CONTEXT_VALID_R2)
      //sequence = PrintRegister("r2", frame_arm->context.iregs[2], sequence);
      AddToRegisterMap(registerMap, "r2", FormatRegisterValue(frame_arm->context.iregs[2]));
    if (frame_arm->context_validity & StackFrameARM::CONTEXT_VALID_R3)
      //sequence = PrintRegister("r3", frame_arm->context.iregs[3], sequence);
      AddToRegisterMap(registerMap, "r3", FormatRegisterValue(frame_arm->context.iregs[3]));

    // General-purpose callee-saves registers.
    if (frame_arm->context_validity & StackFrameARM::CONTEXT_VALID_R4)
      //sequence = PrintRegister("r4", frame_arm->context.iregs[4], sequence);
      AddToRegisterMap(registerMap, "r4", FormatRegisterValue(frame_arm->context.iregs[4]));
    if (frame_arm->context_validity & StackFrameARM::CONTEXT_VALID_R5)
      //sequence = PrintRegister("r5", frame_arm->context.iregs[5], sequence);
      AddToRegisterMap(registerMap, "r5", FormatRegisterValue(frame_arm->context.iregs[5]));
    if (frame_arm->context_validity & StackFrameARM::CONTEXT_VALID_R6)
      //sequence = PrintRegister("r6", frame_arm->context.iregs[6], sequence);
      AddToRegisterMap(registerMap, "r6", FormatRegisterValue(frame_arm->context.iregs[6]));
    if (frame_arm->context_validity & StackFrameARM::CONTEXT_VALID_R7)
      //sequence = PrintRegister("r7", frame_arm->context.iregs[7], sequence);
      AddToRegisterMap(registerMap, "r7", FormatRegisterValue(frame_arm->context.iregs[7]));
    if (frame_arm->context_validity & StackFrameARM::CONTEXT_VALID_R8)
      //sequence = PrintRegister("r8", frame_arm->context.iregs[8], sequence);
      AddToRegisterMap(registerMap, "r8", FormatRegisterValue(frame_arm->context.iregs[8]));
    if (frame_arm->context_validity & StackFrameARM::CONTEXT_VALID_R9)
      //sequence = PrintRegister("r9", frame_arm->context.iregs[9], sequence);
      AddToRegisterMap(registerMap, "r9", FormatRegisterValue(frame_arm->context.iregs[9]));
    if (frame_arm->context_validity & StackFrameARM::CONTEXT_VALID_R10)
      //sequence = PrintRegister("r10", frame_arm->context.iregs[10], sequence);
      AddToRegisterMap(registerMap, "r10", FormatRegisterValue(frame_arm->context.iregs[10]));
    if (frame_arm->context_validity & StackFrameARM::CONTEXT_VALID_R12)
      //sequence = PrintRegister("r12", frame_arm->context.iregs[12], sequence);
      AddToRegisterMap(registerMap, "r12", FormatRegisterValue(frame_arm->context.iregs[12]));

    // Registers with a dedicated or conventional purpose.
    if (frame_arm->context_validity & StackFrameARM::CONTEXT_VALID_FP)
      //sequence = PrintRegister("fp", frame_arm->context.iregs[11], sequence);
      AddToRegisterMap(registerMap, "fp", FormatRegisterValue(frame_arm->context.iregs[11]));
    if (frame_arm->context_validity & StackFrameARM::CONTEXT_VALID_SP)
      //sequence = PrintRegister("sp", frame_arm->context.iregs[13], sequence);
      AddToRegisterMap(registerMap, "sp", FormatRegisterValue(frame_arm->context.iregs[13]));
    if (frame_arm->context_validity & StackFrameARM::CONTEXT_VALID_LR)
      //sequence = PrintRegister("lr", frame_arm->context.iregs[14], sequence);
      AddToRegisterMap(registerMap, "lr", FormatRegisterValue(frame_arm->context.iregs[14]));
    if (frame_arm->context_validity & StackFrameARM::CONTEXT_VALID_PC)
      //sequence = PrintRegister("pc", frame_arm->context.iregs[15], sequence);
      AddToRegisterMap(registerMap, "pc", FormatRegisterValue(frame_arm->context.iregs[15]));
  } else if (cpu == "arm64") {
    using google_breakpad::StackFrameARM64;
    const StackFrameARM64* frame_arm64 =
      reinterpret_cast<const StackFrameARM64*>(frame);

    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X0) {
      //sequence = 
          //PrintRegister64("x0", frame_arm64->context.iregs[0], sequence);
      AddToRegisterMap(registerMap, "x0", FormatRegister64Value(frame_arm64->context.iregs[0]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X1) {
      //sequence = 
          //PrintRegister64("x1", frame_arm64->context.iregs[1], sequence);
      AddToRegisterMap(registerMap, "x1", FormatRegister64Value(frame_arm64->context.iregs[1]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X2) {
      //sequence = 
          //PrintRegister64("x2", frame_arm64->context.iregs[2], sequence);
      AddToRegisterMap(registerMap, "x2", FormatRegister64Value(frame_arm64->context.iregs[2]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X3) {
      //sequence = 
          //PrintRegister64("x3", frame_arm64->context.iregs[3], sequence);
      AddToRegisterMap(registerMap, "x3", FormatRegister64Value(frame_arm64->context.iregs[3]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X4) {
      //sequence = 
          //PrintRegister64("x4", frame_arm64->context.iregs[4], sequence);
      AddToRegisterMap(registerMap, "x4", FormatRegister64Value(frame_arm64->context.iregs[4]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X5) {
      //sequence = 
          //PrintRegister64("x5", frame_arm64->context.iregs[5], sequence);
      AddToRegisterMap(registerMap, "x5", FormatRegister64Value(frame_arm64->context.iregs[5]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X6) {
      //sequence = 
          //PrintRegister64("x6", frame_arm64->context.iregs[6], sequence);
      AddToRegisterMap(registerMap, "x6", FormatRegister64Value(frame_arm64->context.iregs[6]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X7) {
      //sequence = 
          //PrintRegister64("x7", frame_arm64->context.iregs[7], sequence);
      AddToRegisterMap(registerMap, "x7", FormatRegister64Value(frame_arm64->context.iregs[7]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X8) {
      //sequence = 
          //PrintRegister64("x8", frame_arm64->context.iregs[8], sequence);
      AddToRegisterMap(registerMap, "x8", FormatRegister64Value(frame_arm64->context.iregs[8]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X9) {
      //sequence = 
          //PrintRegister64("x9", frame_arm64->context.iregs[9], sequence);
      AddToRegisterMap(registerMap, "x9", FormatRegister64Value(frame_arm64->context.iregs[9]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X10) {
      //sequence = 
          //PrintRegister64("x10", frame_arm64->context.iregs[10], sequence);
      AddToRegisterMap(registerMap, "x10", FormatRegister64Value(frame_arm64->context.iregs[10]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X11) {
      //sequence = 
          //PrintRegister64("x11", frame_arm64->context.iregs[11], sequence);
      AddToRegisterMap(registerMap, "x11", FormatRegister64Value(frame_arm64->context.iregs[11]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X12) {
      //sequence = 
          //PrintRegister64("x12", frame_arm64->context.iregs[12], sequence);
      AddToRegisterMap(registerMap, "x12", FormatRegister64Value(frame_arm64->context.iregs[12]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X13) {
      //sequence = 
          //PrintRegister64("x13", frame_arm64->context.iregs[13], sequence);
      AddToRegisterMap(registerMap, "x13", FormatRegister64Value(frame_arm64->context.iregs[13]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X14) {
      //sequence = 
          //PrintRegister64("x14", frame_arm64->context.iregs[14], sequence);
      AddToRegisterMap(registerMap, "x14", FormatRegister64Value(frame_arm64->context.iregs[14]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X15) {
      //sequence = 
          //PrintRegister64("x15", frame_arm64->context.iregs[15], sequence);
      AddToRegisterMap(registerMap, "x15", FormatRegister64Value(frame_arm64->context.iregs[15]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X16) {
      //sequence = 
          //PrintRegister64("x16", frame_arm64->context.iregs[16], sequence);
      AddToRegisterMap(registerMap, "x16", FormatRegister64Value(frame_arm64->context.iregs[16]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X17) {
      //sequence = 
          //PrintRegister64("x17", frame_arm64->context.iregs[17], sequence);
      AddToRegisterMap(registerMap, "x17", FormatRegister64Value(frame_arm64->context.iregs[17]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X18) {
      //sequence = 
          //PrintRegister64("x18", frame_arm64->context.iregs[18], sequence);
      AddToRegisterMap(registerMap, "x18", FormatRegister64Value(frame_arm64->context.iregs[18]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X19) {
      //sequence = 
          //PrintRegister64("x19", frame_arm64->context.iregs[19], sequence);
      AddToRegisterMap(registerMap, "x19", FormatRegister64Value(frame_arm64->context.iregs[19]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X20) {
      //sequence = 
          //PrintRegister64("x20", frame_arm64->context.iregs[20], sequence);
      AddToRegisterMap(registerMap, "x20", FormatRegister64Value(frame_arm64->context.iregs[20]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X21) {
      //sequence = 
          //PrintRegister64("x21", frame_arm64->context.iregs[21], sequence);
      AddToRegisterMap(registerMap, "x21", FormatRegister64Value(frame_arm64->context.iregs[21]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X22) {
      //sequence = 
          //PrintRegister64("x22", frame_arm64->context.iregs[22], sequence);
      AddToRegisterMap(registerMap, "x22", FormatRegister64Value(frame_arm64->context.iregs[22]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X23) {
      //sequence = 
          //PrintRegister64("x23", frame_arm64->context.iregs[23], sequence);
      AddToRegisterMap(registerMap, "x23", FormatRegister64Value(frame_arm64->context.iregs[23]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X24) {
      //sequence = 
          //PrintRegister64("x24", frame_arm64->context.iregs[24], sequence);
      AddToRegisterMap(registerMap, "x24", FormatRegister64Value(frame_arm64->context.iregs[24]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X25) {
      //sequence = 
          //PrintRegister64("x25", frame_arm64->context.iregs[25], sequence);
      AddToRegisterMap(registerMap, "x25", FormatRegister64Value(frame_arm64->context.iregs[25]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X26) {
      //sequence = 
          //PrintRegister64("x26", frame_arm64->context.iregs[26], sequence);
      AddToRegisterMap(registerMap, "x26", FormatRegister64Value(frame_arm64->context.iregs[26]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X27) {
      //sequence = 
          //PrintRegister64("x27", frame_arm64->context.iregs[27], sequence);
      AddToRegisterMap(registerMap, "x27", FormatRegister64Value(frame_arm64->context.iregs[27]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_X28) {
      //sequence = 
          //PrintRegister64("x28", frame_arm64->context.iregs[28], sequence);
      AddToRegisterMap(registerMap, "x28", FormatRegister64Value(frame_arm64->context.iregs[28]));
    }

    // Registers with a dedicated or conventional purpose.
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_FP) {
      //sequence = 
          //PrintRegister64("fp", frame_arm64->context.iregs[29], sequence);
      AddToRegisterMap(registerMap, "fp", FormatRegister64Value(frame_arm64->context.iregs[29]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_LR) {
      //sequence = 
          //PrintRegister64("lr", frame_arm64->context.iregs[30], sequence);
      AddToRegisterMap(registerMap, "lr", FormatRegister64Value(frame_arm64->context.iregs[30]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_SP) {
      //sequence = 
          //PrintRegister64("sp", frame_arm64->context.iregs[31], sequence);
      AddToRegisterMap(registerMap, "sp", FormatRegister64Value(frame_arm64->context.iregs[31]));
    }
    if (frame_arm64->context_validity & StackFrameARM64::CONTEXT_VALID_PC) {
      //sequence = 
          //PrintRegister64("pc", frame_arm64->context.iregs[32], sequence);
      AddToRegisterMap(registerMap, "pc", FormatRegister64Value(frame_arm64->context.iregs[32]));
    }
  } else if ((cpu == "mips") || (cpu == "mips64")) {
    using google_breakpad::StackFrameMIPS;
    const StackFrameMIPS* frame_mips =
      reinterpret_cast<const StackFrameMIPS*>(frame);

    if (frame_mips->context_validity & StackFrameMIPS::CONTEXT_VALID_GP)
      //sequence = PrintRegister64("gp",
                    //frame_mips->context.iregs[MD_CONTEXT_MIPS_REG_GP],
                    //sequence);
      AddToRegisterMap(registerMap, "gp", FormatRegister64Value(frame_mips->context.iregs[MD_CONTEXT_MIPS_REG_GP]));
    if (frame_mips->context_validity & StackFrameMIPS::CONTEXT_VALID_SP)
      //sequence = PrintRegister64("sp",
                    //frame_mips->context.iregs[MD_CONTEXT_MIPS_REG_SP],
                    //sequence);
      AddToRegisterMap(registerMap, "sp", FormatRegister64Value(frame_mips->context.iregs[MD_CONTEXT_MIPS_REG_SP]));
    if (frame_mips->context_validity & StackFrameMIPS::CONTEXT_VALID_FP)
      //sequence = PrintRegister64("fp",
                    //frame_mips->context.iregs[MD_CONTEXT_MIPS_REG_FP],
                    //sequence);
      AddToRegisterMap(registerMap, "fp", FormatRegister64Value(frame_mips->context.iregs[MD_CONTEXT_MIPS_REG_FP]));
    if (frame_mips->context_validity & StackFrameMIPS::CONTEXT_VALID_RA)
      //sequence = PrintRegister64("ra",
                    //frame_mips->context.iregs[MD_CONTEXT_MIPS_REG_RA],
                    //sequence);
      AddToRegisterMap(registerMap, "ra", FormatRegister64Value(frame_mips->context.iregs[MD_CONTEXT_MIPS_REG_RA]));
    if (frame_mips->context_validity & StackFrameMIPS::CONTEXT_VALID_PC)
      //sequence = PrintRegister64("pc", frame_mips->context.epc, sequence);
      AddToRegisterMap(registerMap, "pc", FormatRegister64Value(frame_mips->context.epc));

    // Save registers s0-s7
    if (frame_mips->context_validity & StackFrameMIPS::CONTEXT_VALID_S0)
      //sequence = PrintRegister64("s0",
                    //frame_mips->context.iregs[MD_CONTEXT_MIPS_REG_S0],
                    //sequence);
      AddToRegisterMap(registerMap, "s0", FormatRegister64Value(frame_mips->context.iregs[MD_CONTEXT_MIPS_REG_S0]));
    if (frame_mips->context_validity & StackFrameMIPS::CONTEXT_VALID_S1)
      //sequence = PrintRegister64("s1",
                    //frame_mips->context.iregs[MD_CONTEXT_MIPS_REG_S1],
                    //sequence);
      AddToRegisterMap(registerMap, "s1", FormatRegister64Value(frame_mips->context.iregs[MD_CONTEXT_MIPS_REG_S1]));
    if (frame_mips->context_validity & StackFrameMIPS::CONTEXT_VALID_S2)
      //sequence = PrintRegister64("s2",
                    //frame_mips->context.iregs[MD_CONTEXT_MIPS_REG_S2],
                    //sequence);
      AddToRegisterMap(registerMap, "s2", FormatRegister64Value(frame_mips->context.iregs[MD_CONTEXT_MIPS_REG_S2]));
    if (frame_mips->context_validity & StackFrameMIPS::CONTEXT_VALID_S3)
      //sequence = PrintRegister64("s3",
                    //frame_mips->context.iregs[MD_CONTEXT_MIPS_REG_S3],
                    //sequence);
      AddToRegisterMap(registerMap, "s3", FormatRegister64Value(frame_mips->context.iregs[MD_CONTEXT_MIPS_REG_S3]));
    if (frame_mips->context_validity & StackFrameMIPS::CONTEXT_VALID_S4)
      //sequence = PrintRegister64("s4",
                    //frame_mips->context.iregs[MD_CONTEXT_MIPS_REG_S4],
                    //sequence);
      AddToRegisterMap(registerMap, "s4", FormatRegister64Value(frame_mips->context.iregs[MD_CONTEXT_MIPS_REG_S4]));
    if (frame_mips->context_validity & StackFrameMIPS::CONTEXT_VALID_S5)
      //sequence = PrintRegister64("s5",
                    //frame_mips->context.iregs[MD_CONTEXT_MIPS_REG_S5],
                    //sequence);
      AddToRegisterMap(registerMap, "s5", FormatRegister64Value(frame_mips->context.iregs[MD_CONTEXT_MIPS_REG_S5]));
    if (frame_mips->context_validity & StackFrameMIPS::CONTEXT_VALID_S6)
      //sequence = PrintRegister64("s6",
                    //frame_mips->context.iregs[MD_CONTEXT_MIPS_REG_S6],
                    //sequence);
      AddToRegisterMap(registerMap, "s6", FormatRegister64Value(frame_mips->context.iregs[MD_CONTEXT_MIPS_REG_S6]));
    if (frame_mips->context_validity & StackFrameMIPS::CONTEXT_VALID_S7)
      //sequence = PrintRegister64("s7",
                    //frame_mips->context.iregs[MD_CONTEXT_MIPS_REG_S7],
                    //sequence);
      AddToRegisterMap(registerMap, "s7", FormatRegister64Value(frame_mips->context.iregs[MD_CONTEXT_MIPS_REG_S7]));
    }

  //return nullptr;
}

static Register* getRegisters(const StackFrame* frame, const string& cpu) {
  //const StackFrame* frame = stack->frames()->at(0);
  //if (!frame) {
  //  throw std::runtime_error("Bad frame index");
  //}
  std::vector<RegisterData> registerDataVector;
  RegisterData* registerDataArray = nullptr;
  Register* registers = nullptr;

  // call function in separate file, pass in frame & cpu, get back map<string, string> of register data
  std::map<std::string, std::string> registerMap;
  getRegisterData(registerMap, frame, cpu);

  if (registerMap.size() > 0) {
    registerDataArray = (RegisterData*)malloc(sizeof(RegisterData) * registerMap.size());
    if (!registerDataArray) {
      throw std::bad_alloc();
    }

    uint32_t registerDataIndex = 0;
    for (std::map<std::string, std::string>::const_iterator iterator =
        registerMap.begin();
        iterator != registerMap.end(); ++iterator) {
          RegisterData rd = {.registerName = duplicate(iterator->first.c_str()), .registerValue = duplicate(iterator->second.c_str())};
          registerDataArray[registerDataIndex++] = rd;
    }

    Register r = {.frameIndex = 0, .registerDataCount = static_cast<int>(registerDataIndex), .registerValues = registerDataArray};
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
