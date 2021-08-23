#include "bugsnag_stackwalk_wrapper.h"
#include "bugsnag_register_reader.h"

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

#include "google_breakpad/common/minidump_format.h"

using google_breakpad::BasicSourceLineResolver;
using google_breakpad::CallStack;
using google_breakpad::HexString;
using google_breakpad::Minidump;
using google_breakpad::MinidumpCrashpadInfo;
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
static char* duplicate(const std::string& s) {
  char* str = strdup(s.c_str());
  if (!str) {
    throw std::bad_alloc();
  }
  return str;
}

// Calls free on passed pointer and sets it to nullptr
static void freeAndInvalidate(void** p) {
  free((void*)*p);
  *p = nullptr;
}

static void destroyStackframe(void* self) {
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

static void destroyStacktrace(Stacktrace* stacktrace) {
  if (!stacktrace)
    return;

  for (int i = 0; i < stacktrace->frameCount; ++i) {
    destroyStackframe(&stacktrace->frames[i]);
  }
  freeAndInvalidate((void**)&stacktrace->frames);
}

static void destroyRegisterValue(RegisterValue* reg) {
  if (!reg)
    return;

  freeAndInvalidate((void**)&reg->name);
  freeAndInvalidate((void**)&reg->value);
}

static void destroyRegisters(Register* registers) {
  if (!registers)
    return;

  for (int i = 0; i < registers->registerValueCount; ++i) {
    destroyRegisterValue(&registers->registerValues[i]);
  }
  freeAndInvalidate((void**)&registers->registerValues);
}

static void destroyException(Exception* exception) {
  if (!exception)
    return;

  freeAndInvalidate((void**)&exception->errorClass);
  freeAndInvalidate((void**)&exception->crashAddress);
  destroyStacktrace(&exception->stacktrace);
  destroyRegisters(exception->registers);
}

static void destroyApp(App* app) {
  if (!app)
    return;

  freeAndInvalidate((void**)&app->binaryArch);
}

static void destroyDevice(Device* device) {
  if (!device)
    return;

  freeAndInvalidate((void**)&device->osName);
  freeAndInvalidate((void**)&device->osVersion);
}

static void destroyThread(Thread* thread) {
  if (!thread)
    return;

  destroyStacktrace(&thread->stacktrace);
}

static void destroySimpleAnnotation(SimpleAnnotation* simpleAnnotation) {
  if (!simpleAnnotation)
    return;

  freeAndInvalidate((void**)&simpleAnnotation->key);
  freeAndInvalidate((void**)&simpleAnnotation->value);
}

static void destroyListAnnotation(ListAnnotation* listAnnotation) {
  if (!listAnnotation)
    return;

  freeAndInvalidate((void**)&listAnnotation->value);
}

static void destroyModuleInfo(ModuleInfo* moduleInfo) {
  if (!moduleInfo)
    return;

  freeAndInvalidate((void**)&moduleInfo->moduleName);

  for (int i = 0; i < moduleInfo->simpleAnnotationCount; ++i) {
    destroySimpleAnnotation(&moduleInfo->simpleAnnotations[i]);
  }
  freeAndInvalidate((void**)&moduleInfo->simpleAnnotations);

  for (int i = 0; i < moduleInfo->listAnnotationCount; ++i) {
    destroyListAnnotation(&moduleInfo->listAnnotations[i]);
  }
  freeAndInvalidate((void**)&moduleInfo->listAnnotations);
}

static void destroyCrashpadInfo(CrashpadInfo* crashpadInfo) {
  if (!crashpadInfo)
    return;

  freeAndInvalidate((void**)&crashpadInfo->clientId);
  freeAndInvalidate((void**)&crashpadInfo->reportId);
  for (int i = 0; i < crashpadInfo->simpleAnnotationCount; ++i) {
    destroySimpleAnnotation(&crashpadInfo->simpleAnnotations[i]);
  }
  freeAndInvalidate((void**)&crashpadInfo->simpleAnnotations);

  for (int i = 0; i < crashpadInfo->moduleCount; ++i) {
    destroyModuleInfo(&crashpadInfo->moduleInfo[i]);
  }
  freeAndInvalidate((void**)&crashpadInfo->moduleInfo);
}

static void destroyMinidumpMetadata(MinidumpMetadata* minidumpMetadata) {
  if (!minidumpMetadata)
    return;

  destroyCrashpadInfo(&minidumpMetadata->crashpadInfo);
}

static void destroyEvent(Event* event) {
  if (!event)
    return;

  destroyApp(&event->app);
  destroyDevice(&event->device);
  destroyException(&event->exception);
  for (int i = 0; i < event->threadCount; ++i) {
    destroyThread(&event->threads[i]);
  }
  freeAndInvalidate((void**)&event->threads);
  destroyMinidumpMetadata(&event->metaData);
}

static void destroyModuleDetails(ModuleDetails* moduleDetails) {
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

static void destroyWrappedEvent(WrappedEvent* wrappedEvent) {
  if (!wrappedEvent)
    return;

  freeAndInvalidate((void**)&wrappedEvent->pstrErr);
  destroyEvent(&wrappedEvent->event);
}

static void destroyWrappedModuleDetails(
    WrappedModuleDetails* wrappedModuleDetails) {
  if (!wrappedModuleDetails)
    return;

  freeAndInvalidate((void**)&wrappedModuleDetails->pstrErr);
  destroyModuleDetails(&wrappedModuleDetails->moduleDetails);
}

// Gets the index of the thread that requested a dump be written
static int getErrorReportingThreadIndex(const ProcessState& process_state) {
  int index = process_state.requesting_thread();
  // If the dump thread was not available then default to the first available
  // thread
  if (index == -1) {
    index = 0;
  }
  return index;
}

// Gets a friendly version of the stack frame trust value
static string getFriendlyTrustValue(StackFrame::FrameTrust stackFrameTrust) {
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

static Register getRegisterForStackFrame(const StackFrame* frame,
                                         const string& cpu) {
  RegisterValue* registerArray = nullptr;
  // frameIndex of -1 indicates it has not been set - caller must set this field
  Register reg = {.frameIndex = -1};

  std::map<std::string, std::string> registerMap =
      bugsnag_breakpad::getRegisterValues(frame, cpu);

  if (registerMap.size() > 0) {
    registerArray =
        (RegisterValue*)malloc(sizeof(RegisterValue) * registerMap.size());
    if (!registerArray) {
      throw std::bad_alloc();
    }

    uint32_t registerIndex = 0;
    for (std::map<std::string, std::string>::const_iterator iterator =
             registerMap.begin();
         iterator != registerMap.end(); ++iterator) {
      RegisterValue regValue = {.name = duplicate(iterator->first.c_str()),
                                .value = duplicate(iterator->second.c_str())};
      registerArray[registerIndex++] = regValue;
    }

    reg.registerValueCount = static_cast<int>(registerIndex);
    reg.registerValues = registerArray;
  }

  return reg;
}

// Maps the information from a minidump into our Event struct
static Event getEvent(const ProcessState& process_state) {
  Stacktrace s = getStack(
      process_state.threads()->at(getErrorReportingThreadIndex(process_state)));

  string cpu = process_state.system_info()->cpu;
  const CallStack* stack =
      process_state.threads()->at(getErrorReportingThreadIndex(process_state));

  // currently retrieve the registers for only the top stack frame
  const uint32_t NUMBER_OF_STACK_FRAMES = 1;
  Register* registers =
      (Register*)malloc(sizeof(Register) * NUMBER_OF_STACK_FRAMES);
  if (!registers) {
    throw std::bad_alloc();
  }

  // get the exception register info
  uint32_t framesAdded = 0;
  for (uint32_t frameIndex; frameIndex < NUMBER_OF_STACK_FRAMES &&
                            frameIndex < stack->frames()->size();
       ++frameIndex) {
    const StackFrame* frame = stack->frames()->at(frameIndex);
    Register r = getRegisterForStackFrame(frame, cpu);
    r.frameIndex = frameIndex;
    registers[frameIndex] = r;
    ++framesAdded;
  }

  Exception e = {.stacktrace = s,
                 .errorClass = duplicate(process_state.crash_reason())};
  string crashAddress = HexString(process_state.crash_address());
  if (crashAddress != "") {
    e.crashAddress = duplicate(crashAddress);
  }
  e.registerCount = framesAdded;
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
static string getFriendlyFailureReason(ProcessResult process_result) {
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

static string MDGUIDToString(const MDGUID& uuid) {
  char buf[37];
  snprintf(buf, sizeof(buf), "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
           uuid.data1, uuid.data2, uuid.data3, uuid.data4[0], uuid.data4[1],
           uuid.data4[2], uuid.data4[3], uuid.data4[4], uuid.data4[5],
           uuid.data4[6], uuid.data4[7]);
  return std::string(buf);
}

static uint32_t getSimpleAnnotations(MinidumpCrashpadInfo& mci,
                                     SimpleAnnotation** simpleAnnotationArray) {
  const std::map<std::string, std::string>* simpleAnnotations =
      mci.GetSimpleAnnotations();
  if (!simpleAnnotations) {
    return 0;
  }

  const uint32_t simpleAnnotationCount =
      (simpleAnnotations ? simpleAnnotations->size() : 0);
  if (simpleAnnotationCount > 0) {
    *simpleAnnotationArray = (SimpleAnnotation*)malloc(
        sizeof(SimpleAnnotation) * simpleAnnotationCount);
    if (!*simpleAnnotationArray) {
      throw std::bad_alloc();
    }

    uint32_t simpleAnnotationIndex = 0;
    for (std::map<std::string, std::string>::const_iterator iterator =
             simpleAnnotations->begin();
         iterator != simpleAnnotations->end(); ++iterator) {
      SimpleAnnotation simpleAnnotation = {
          .key = duplicate(iterator->first.c_str()),
          .value = duplicate(iterator->second.c_str())};
      (*simpleAnnotationArray)[simpleAnnotationIndex++] = simpleAnnotation;
    }
  }
  return simpleAnnotationCount;
}

static uint32_t getListAnnotationsForModule(
    const uint32_t module_index,
    const std::vector<std::vector<std::string>>* infoListAnnotations,
    ListAnnotation** modulesListAnnotationArray) {
  if (!infoListAnnotations) {
    return 0;
  }

  const uint32_t modulesListAnnotationCount =
      (*infoListAnnotations)[module_index].size();
  if (modulesListAnnotationCount > 0) {
    *modulesListAnnotationArray = (ListAnnotation*)malloc(
        sizeof(ListAnnotation) * modulesListAnnotationCount);
    if (!*modulesListAnnotationArray) {
      throw std::bad_alloc();
    }
  }

  for (uint32_t annotation_index = 0;
       annotation_index < modulesListAnnotationCount; ++annotation_index) {
    ListAnnotation listAnnotation = {
        .value = duplicate(
            (*infoListAnnotations)[module_index][annotation_index].c_str())};
    (*modulesListAnnotationArray)[annotation_index] = listAnnotation;
  }

  return modulesListAnnotationCount;
}

static uint32_t getSimpleAnnotationsForModule(
    const uint32_t module_index,
    const std::vector<std::map<std::string, std::string>>*
        infoSimpleAnnotations,
    SimpleAnnotation** modulesSimpleAnnotationArray) {
  if (!infoSimpleAnnotations) {
    return 0;
  }

  const uint32_t modulesSimpleAnnotationCount =
      (*infoSimpleAnnotations)[module_index].size();
  if (modulesSimpleAnnotationCount > 0) {
    *modulesSimpleAnnotationArray = (SimpleAnnotation*)malloc(
        sizeof(SimpleAnnotation) * modulesSimpleAnnotationCount);
    if (!*modulesSimpleAnnotationArray) {
      throw std::bad_alloc();
    }
  }

  uint32_t simpleAnnotationIndex = 0;
  for (std::map<std::string, std::string>::const_iterator iterator =
           (*infoSimpleAnnotations)[module_index].begin();
       iterator != (*infoSimpleAnnotations)[module_index].end(); ++iterator) {
    if (simpleAnnotationIndex >= modulesSimpleAnnotationCount) {
      BPLOG(ERROR) << "Array out of bounds";
      break;
    }
    SimpleAnnotation simpleAnnotation = {
        .key = duplicate(iterator->first.c_str()),
        .value = duplicate(iterator->second.c_str())};
    (*modulesSimpleAnnotationArray)[simpleAnnotationIndex++] = simpleAnnotation;
  }
  return modulesSimpleAnnotationCount;
}

static uint32_t getModuleAnnotations(Minidump& dump,
                                     MinidumpCrashpadInfo& mci,
                                     ModuleInfo** moduleInfoArray) {
  const uint32_t moduleInfoCount =
      ((mci.GetModuleCrashpadInfoLinks())
           ? mci.GetModuleCrashpadInfoLinks()->size()
           : 0);
  if (moduleInfoCount == 0) {
    return 0;
  }

  const std::vector<std::vector<std::string>>* infoListAnnotations =
      mci.GetInfoListAnnotations();

  const std::vector<std::map<std::string, std::string>>* infoSimpleAnnotations =
      mci.GetInfoSimpleAnnotations();

  if (!infoListAnnotations && !infoSimpleAnnotations) {
    return 0;
  }

  std::vector<ModuleInfo> moduleInfoVector;
  MinidumpModuleList* module_list = dump.GetModuleList();
  if (!module_list) {
    BPLOG(ERROR) << "Cannot get module list for minidump";
    return 0;
  }

  for (uint32_t module_index = 0; module_index < moduleInfoCount;
       ++module_index) {
    ListAnnotation* modulesListAnnotationArray = nullptr;
    SimpleAnnotation* modulesSimpleAnnotationArray = nullptr;

    string code_file = "";
    const MinidumpModule* module = module_list->GetModuleAtIndex(module_index);
    if (module) {
      code_file = PathnameStripper::File(module->code_file());
    }
    if (code_file == "") {
      BPLOG(ERROR) << "Cannot get module name for minidump";
      continue;
    }

    const uint32_t modulesListAnnotationCount = getListAnnotationsForModule(
        module_index, infoListAnnotations, &modulesListAnnotationArray);

    const uint32_t modulesSimpleAnnotationCount = getSimpleAnnotationsForModule(
        module_index, infoSimpleAnnotations, &modulesSimpleAnnotationArray);

    if ((modulesListAnnotationCount == 0) &&
        (modulesSimpleAnnotationCount == 0)) {
      // only add modules that have some list annotations or simple annotations
      continue;
    }

    ModuleInfo moduleInfo = {
        .moduleName = duplicate(code_file),
        .listAnnotationCount = static_cast<int>(modulesListAnnotationCount),
        .listAnnotations = modulesListAnnotationArray,
        .simpleAnnotationCount = static_cast<int>(modulesSimpleAnnotationCount),
        .simpleAnnotations = modulesSimpleAnnotationArray,
    };
    moduleInfoVector.push_back(moduleInfo);
  }

  const uint32_t moduleInfoItemCount = moduleInfoVector.size();
  if (moduleInfoItemCount > 0) {
    *moduleInfoArray =
        (ModuleInfo*)malloc(sizeof(ModuleInfo) * moduleInfoItemCount);
    if (!*moduleInfoArray) {
      throw std::bad_alloc();
    }

    uint32_t moduleIndex = 0;
    for (std::vector<ModuleInfo>::const_iterator iterator =
             moduleInfoVector.begin();
         iterator != moduleInfoVector.end(); ++iterator) {
      (*moduleInfoArray)[moduleIndex++] = std::move(*iterator);
    }
  }
  return moduleInfoItemCount;
}

MinidumpMetadata getMinidumpMetadata(Minidump& dump) {
  SimpleAnnotation* simpleAnnotationArray = nullptr;
  ModuleInfo* moduleInfoArray = nullptr;

  MinidumpCrashpadInfo* mci = dump.GetCrashpadInfo();
  if (!mci) {
    return MinidumpMetadata{};
  }

  const uint32_t simpleAnnotationCount =
      getSimpleAnnotations(*mci, &simpleAnnotationArray);

  const uint32_t moduleInfoCount =
      getModuleAnnotations(dump, *mci, &moduleInfoArray);

  string report_id = "";
  string client_id = "";
  if (mci->crashpad_info()) {
    report_id = MDGUIDToString(mci->crashpad_info()->report_id);
    client_id = MDGUIDToString(mci->crashpad_info()->client_id);
  }

  CrashpadInfo crashpadInfo = {
      .reportId = duplicate(report_id),
      .clientId = duplicate(client_id),
      .simpleAnnotationCount = static_cast<int>(simpleAnnotationCount),
      .simpleAnnotations = simpleAnnotationArray,
      .moduleCount = static_cast<int>(moduleInfoCount),
      .moduleInfo = moduleInfoArray};

  MinidumpMetadata minidumpMetadata = {.crashpadInfo = crashpadInfo};

  return minidumpMetadata;
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

    // Populate metadata
    result.event.metaData = getMinidumpMetadata(dump);

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
