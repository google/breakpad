#include <map>
#include <string>

#include "google_breakpad/processor/stack_frame_cpu.h"

using google_breakpad::StackFrame;

namespace bugsnag_breakpad {

static std::string FormatRegisterValue(uint32_t value);

static std::string FormatRegister64Value(uint64_t value);

static void AddToRegisterMap(std::map<std::string, std::string>& registerMap,
                             const char* name,
                             const std::string value);

void getRegisterData(std::map<std::string, std::string>& registerMap,
                     const StackFrame* frame,
                     const std::string& cpu);

}  // namespace bugsnag_breakpad
