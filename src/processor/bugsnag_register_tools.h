#include <string>
#include <map>

#include "google_breakpad/processor/stack_frame_cpu.h"

using google_breakpad::StackFrame;

namespace bugsnag_breakpad {

static std::string XXXFormatRegisterValue(uint32_t value);

static std::string XXXFormatRegister64Value(uint64_t value);

static void XXXAddToRegisterMap(std::map<std::string, std::string>& registerMap,
                             const char* name,
                             const std::string value);

static void XXXgetRegisterData(std::map<std::string, std::string>& registerMap,
                            const StackFrame* frame,
                            const std::string& cpu);

} // namespace bugsnag_breakpad