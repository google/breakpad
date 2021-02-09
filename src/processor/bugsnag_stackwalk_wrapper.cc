#include "bugsnag_stackwalk_wrapper.h"

#include "common/scoped_ptr.h"
#include "logging.h"
#include "simple_symbol_supplier.h"

#include "google_breakpad/processor/basic_source_line_resolver.h"
#include "google_breakpad/processor/minidump_processor.h"
#include "google_breakpad/processor/process_state.h"
#include "google_breakpad/processor/call_stack.h"
#include "google_breakpad/processor/stack_frame_cpu.h"

using google_breakpad::BasicSourceLineResolver;
using google_breakpad::CallStack;
using google_breakpad::HexString;
using google_breakpad::Minidump;
using google_breakpad::MinidumpMemoryList;
using google_breakpad::MinidumpModule;
using google_breakpad::MinidumpModuleList;
using google_breakpad::MinidumpProcessor;
using google_breakpad::MinidumpThreadList;
using google_breakpad::ProcessState;
using google_breakpad::scoped_ptr;
using google_breakpad::SimpleSymbolSupplier;
using google_breakpad::StackFrame;

// Maps the stacktrace information from a minidump into our Stacktrace struct
static Stacktrace getStack(int thread_num, const CallStack* stack)  {
  int frame_count = stack->frames()->size();

  std::vector<Stackframe> frames;

  for (int frame_index = 0; frame_index < frame_count; ++frame_index) {
    const StackFrame* frame = stack->frames()->at(frame_index);

    string returnAddress;
    string frameAddress;
    string filename = "";
    string moduleId = "";
    string moduleName = "";
    if (frame->module) {
      returnAddress = HexString(frame->ReturnAddress() - frame->module->base_address());
      frameAddress = HexString(frame->instruction - frame->module->base_address());
      filename = frame->module->code_file();
      moduleId = frame->module->debug_identifier();
      moduleName = frame->module->debug_file();
    } else {
      returnAddress = HexString(frame->ReturnAddress());
      frameAddress = HexString(frame->instruction);
    }
    
    Stackframe f = {
      .filename = strdup(filename.c_str()),
      .method = strdup(returnAddress.c_str()),
      .frameAddress = strdup(frameAddress.c_str()),
      .moduleId = strdup(moduleId.c_str()),
      .moduleName = strdup(moduleName.c_str())
    };
    frames.push_back(f);
  }

  Stackframe* stackframes = new Stackframe[frame_count];
  for (int frame_index = 0; frame_index < frame_count; ++frame_index) {
    stackframes[frame_index] = frames.at(frame_index);
  }

  Stacktrace s = {
    .frameCount = frame_count,
    .frames = stackframes
  };

  return s;
}

// Maps the information from a minidump into our Event struct
Event getEvent(const ProcessState& process_state) {
  Stacktrace s = getStack(1, process_state.threads()->at(0));

  Exception e = {
    .stacktrace = s,
    .errorClass = strdup(process_state.crash_reason().c_str())
  };

  int uptime = 0;
  if (process_state.time_date_stamp() != 0 &&
      process_state.process_create_time() != 0 &&
      process_state.time_date_stamp() >= process_state.process_create_time()) {
    uptime = process_state.time_date_stamp() - process_state.process_create_time() * 1000;
  }

  App app = {
    .binaryArch = strdup(process_state.system_info()->cpu.c_str()),
    .duration = uptime // TODO - Handle this being empty
  };

  Device device = {
    .osName = strdup(process_state.system_info()->os.data()),
    .osVersion = strdup(process_state.system_info()->os_version.c_str()) // TODO split build from version (but we may want to do that in the service)
  };

  // TODO - Parse and add threads

  Event returnEvent = {
    .exception = e,
    .app = app,
    .device = device
  };

  return returnEvent;
}

// Get the details of the modules in a minidump
ModuleDetails GetModuleDetails(const char* minidump_filename) {
  Minidump dump(minidump_filename);
  if (!dump.Read()) {
    // TODO improve error handling
    fprintf(stderr, "Minidump could not be read\n");
  }

  ModuleDetails module_details = {
    .moduleCount = 0
  };

  MinidumpModuleList* module_list = dump.GetModuleList();
  if (module_list) {
    module_details.moduleCount = module_list->module_count();

    char **module_ids = (char**)malloc(sizeof(char*) * module_list->module_count());
    char **module_names = (char**)malloc(sizeof(char*) * module_list->module_count());

    for (unsigned int i = 0; i < module_list->module_count(); i++) {
      const MinidumpModule* module = module_list->GetModuleAtIndex(i);

      module_ids[i] = (char*)malloc(sizeof(char) * strlen(module->debug_identifier().c_str()));
      strcpy(module_ids[i], module->debug_identifier().c_str());
      module_details.moduleIds = module_ids;

      module_names[i] = (char*)malloc(sizeof(char) * strlen(module->debug_file().c_str()));
      strcpy(module_names[i], module->debug_file().c_str());
      module_details.moduleNames = module_names;
    }
  }

  return module_details;
}

// Gets an Event payload from the minidump.
// Note: Logic for parsing the minidump is based on PrintMinidumpProcess in minidump_stackwalk.cc
// TODO - See if we can disable the logging output
Event GetEventFromMinidump(const char* filename, const char* symbol_path) {

  // Apply a symbol supplier if we've been given a symbol path (to allow the stack data to be used when walking the stacktrace)
  scoped_ptr<SimpleSymbolSupplier> symbol_supplier;
  if (symbol_path != NULL && strlen(symbol_path) > 0) {
    symbol_supplier.reset(new SimpleSymbolSupplier(symbol_path));
  }

  BasicSourceLineResolver resolver;
  MinidumpProcessor minidump_processor(symbol_supplier.get(), &resolver);

  // Increase the maximum number of threads and regions.
  MinidumpThreadList::set_max_threads(std::numeric_limits<uint32_t>::max());
  MinidumpMemoryList::set_max_regions(std::numeric_limits<uint32_t>::max());
  
  // Process the minidump.
  Minidump dump(filename);
  if (!dump.Read()) {
    // TODO improve error handling
    fprintf(stderr, "Minidump could not be read\n");
  }

  ProcessState process_state;
  if (minidump_processor.Process(&dump, &process_state) != google_breakpad::PROCESS_OK) {
      // TODO improve error handling
      fprintf(stderr, "MinidumpProcessor::Process failed\n");
  }

  // Map the process state to an Event struct
  Event returnEvent = getEvent(process_state);

  return returnEvent;
}

// Frees the memory allocated by an Event
// TODO - Check there are no memory leaks
void FreeEvent(Event* event) {
  event->destroy();
}

// Frees the memory allocated by the module details
// TODO - Check there are no memory leaks
void FreeModuleDetails(ModuleDetails* module_details) {
  module_details->destroy();
}