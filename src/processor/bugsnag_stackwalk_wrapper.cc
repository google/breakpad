#include "bugsnag_stackwalk_wrapper.h"

#include "common/scoped_ptr.h"
#include "logging.h"
#include "simple_symbol_supplier.h"

#include <string.h>
#include <limits>
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

void destroyException(Exception* exception) {
  if (!exception)
    return;

  freeAndInvalidate((void**)&exception->errorClass);
  freeAndInvalidate((void**)&exception->crashAddress);
  destroyStacktrace(&exception->stacktrace);
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

void destroySimpleAnnotation(SimpleAnnotation* simpleAnnotation) {
  if (!simpleAnnotation)
    return;

  freeAndInvalidate((void**)&simpleAnnotation->key);
  freeAndInvalidate((void**)&simpleAnnotation->value);
}

void destroyListAnnotation(ListAnnotation* listAnnotation) {
  if (!listAnnotation)
    return;

  freeAndInvalidate((void**)&listAnnotation->value);
}

void destroyModuleInfo(ModuleInfo* moduleInfo) {
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

void destroyCrashpadInfo(CrashpadInfo* crashpadInfo) {
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

void destroyMinidumpMetadata(MinidumpMetadata* minidumpMetadata) {
  if (!minidumpMetadata)
    return;

  destroyCrashpadInfo(&minidumpMetadata->crashpadInfo);
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
  destroyMinidumpMetadata(&event->metadata);
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

// Maps the information from a minidump into our Event struct
Event getEvent(const ProcessState& process_state) {
  Stacktrace s = getStack(
      process_state.threads()->at(getErrorReportingThreadIndex(process_state)));

  Exception e = {.stacktrace = s,
                 .errorClass = duplicate(process_state.crash_reason())};
  string crashAddress = HexString(process_state.crash_address());
  if (crashAddress != "") {
    e.crashAddress = duplicate(crashAddress);
  }

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

string MDGUIDToString(const MDGUID& uuid) {
  char buf[37];
  snprintf(buf, sizeof(buf), "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
           uuid.data1,
           uuid.data2,
           uuid.data3,
           uuid.data4[0],
           uuid.data4[1],
           uuid.data4[2],
           uuid.data4[3],
           uuid.data4[4],
           uuid.data4[5],
           uuid.data4[6],
           uuid.data4[7]);
  return std::string(buf);
}

//
// Swapping routines
//
// Inlining these doesn't increase code size significantly, and it saves
// a whole lot of unnecessary jumping back and forth.
//


// Swapping an 8-bit quantity is a no-op.  This function is only provided
// to account for certain templatized operations that require swapping for
// wider types but handle uint8_t too
// (MinidumpMemoryRegion::GetMemoryAtAddressInternal).
inline void Swap(uint8_t* value) {}

// Optimization: don't need to AND the furthest right shift, because we're
// shifting an unsigned quantity.  The standard requires zero-filling in this
// case.  If the quantities were signed, a bitmask whould be needed for this
// right shift to avoid an arithmetic shift (which retains the sign bit).
// The furthest left shift never needs to be ANDed bitmask.

inline void Swap(uint16_t* value) {
  *value = (*value >> 8) | (*value << 8);
}

inline void Swap(uint32_t* value) {
  *value =  (*value >> 24) |
           ((*value >> 8)  & 0x0000ff00) |
           ((*value << 8)  & 0x00ff0000) |
            (*value << 24);
}

inline void Swap(uint64_t* value) {
  uint32_t* value32 = reinterpret_cast<uint32_t*>(value);
  Swap(&value32[0]);
  Swap(&value32[1]);
  uint32_t temp = value32[0];
  value32[0] = value32[1];
  value32[1] = temp;
}


// Given a pointer to a 128-bit int in the minidump data, set the "low"
// and "high" fields appropriately.
void Normalize128(uint128_struct* value, bool is_big_endian) {
  // The struct format is [high, low], so if the format is big-endian,
  // the most significant bytes will already be in the high field.
  if (!is_big_endian) {
    uint64_t temp = value->low;
    value->low = value->high;
    value->high = temp;
  }
}

// This just swaps each int64 half of the 128-bit value.
// The value should also be normalized by calling Normalize128().
void Swap(uint128_struct* value) {
  Swap(&value->low);
  Swap(&value->high);
}

// Swapping signed integers
inline void Swap(int32_t* value) {
  Swap(reinterpret_cast<uint32_t*>(value));
}

inline void Swap(MDLocationDescriptor* location_descriptor) {
  Swap(&location_descriptor->data_size);
  Swap(&location_descriptor->rva);
}

inline void Swap(MDMemoryDescriptor* memory_descriptor) {
  Swap(&memory_descriptor->start_of_memory_range);
  Swap(&memory_descriptor->memory);
}

inline void Swap(MDGUID* guid) {
  Swap(&guid->data1);
  Swap(&guid->data2);
  Swap(&guid->data3);
  // Don't swap guid->data4[] because it contains 8-bit quantities.
}

inline void Swap(MDSystemTime* system_time) {
  Swap(&system_time->year);
  Swap(&system_time->month);
  Swap(&system_time->day_of_week);
  Swap(&system_time->day);
  Swap(&system_time->hour);
  Swap(&system_time->minute);
  Swap(&system_time->second);
  Swap(&system_time->milliseconds);
}

inline void Swap(MDXStateFeature* xstate_feature) {
  Swap(&xstate_feature->offset);
  Swap(&xstate_feature->size);
}

inline void Swap(MDXStateConfigFeatureMscInfo* xstate_feature_info) {
  Swap(&xstate_feature_info->size_of_info);
  Swap(&xstate_feature_info->context_size);
  Swap(&xstate_feature_info->enabled_features);

  for (size_t i = 0; i < MD_MAXIMUM_XSTATE_FEATURES; i++) {
    Swap(&xstate_feature_info->features[i]);
  }
}

inline void Swap(MDRawSimpleStringDictionaryEntry* entry) {
  Swap(&entry->key);
  Swap(&entry->value);
}

inline void Swap(uint16_t* data, size_t size_in_bytes) {
  size_t data_length = size_in_bytes / sizeof(data[0]);
  for (size_t i = 0; i < data_length; i++) {
    Swap(&data[i]);
  }
}

MinidumpMetadata getMinidumpMetadata(Minidump& dump) {
  google_breakpad::MinidumpCrashpadInfo* minidumpCrashpadInfo = dump.GetCrashpadInfo();
  if (minidumpCrashpadInfo) {

      MDRawCrashpadInfo* rawCrashpadInfo = const_cast<MDRawCrashpadInfo*>(minidumpCrashpadInfo->crashpad_info());
      if (rawCrashpadInfo) {

        MinidumpModuleList* module_list = dump.GetModuleList();
        if (!module_list) {
          BPLOG(ERROR) << "getMinidumpMetadata failed to get module list";
          //result.pstrErr = duplicate("failed to get module list");
          //return result;
        }

        int saCount = 0;
        SimpleAnnotation* sa_array = nullptr;
        uint32_t moduleInfoCount = 0;
        ModuleInfo* moduleInfoArray = nullptr;

        if (dump.swap()) {
          Swap(&rawCrashpadInfo->version);
          Swap(&rawCrashpadInfo->report_id);
          Swap(&rawCrashpadInfo->client_id);
          Swap(&rawCrashpadInfo->simple_annotations);
          Swap(&rawCrashpadInfo->module_list);
        }

        std::map<std::string, std::string> simple_annotations_;
        if (rawCrashpadInfo->simple_annotations.data_size) {
          if (dump.ReadSimpleStringDictionary(
              rawCrashpadInfo->simple_annotations.rva,
              &simple_annotations_)) {

            saCount = simple_annotations_.size();
            sa_array = (SimpleAnnotation*)malloc(sizeof(SimpleAnnotation) * saCount);
            if (!sa_array) {
              // TODO
            }
            int saIndex = 0;
            for (std::map<std::string, std::string>::const_iterator iterator = simple_annotations_.begin();
                iterator != simple_annotations_.end();
                ++iterator) {
              SimpleAnnotation simpleAnnotation = {.key = duplicate(iterator->first.c_str()), .value = duplicate(iterator->second.c_str())};
              BPLOG(ERROR) << "simpleAnnotation: key - " << simpleAnnotation.key << " value - " << simpleAnnotation.value;
              sa_array[saIndex] = simpleAnnotation;

              ++saIndex;
            }
          }
          else {
            BPLOG(ERROR) << "getMinidumpMetadata cannot read simple_annotations";
          }
        }

////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        if (rawCrashpadInfo->module_list.data_size) {
          if (!dump.SeekSet(rawCrashpadInfo->module_list.rva)) {
            BPLOG(ERROR) << "getMinidumpMetadata cannot seek to module_list";
            //return false;
          }

          //uint32_t count;
          if (!dump.ReadBytes(&moduleInfoCount, sizeof(moduleInfoCount))) {
            BPLOG(ERROR) << "getMinidumpMetadata cannot read module_list count";
            //return false;
          }

          if (dump.swap()) {
            Swap(&moduleInfoCount);
          }

          google_breakpad::scoped_array<MDRawModuleCrashpadInfoLink> module_crashpad_info_links(
              new MDRawModuleCrashpadInfoLink[moduleInfoCount]);

          // Read the entire array in one fell swoop, instead of reading one entry
          // at a time in the loop.
          if (!dump.ReadBytes(
                  &module_crashpad_info_links[0],
                  sizeof(MDRawModuleCrashpadInfoLink) * moduleInfoCount)) {
            BPLOG(ERROR)
                << "getMinidumpMetadata could not read Crashpad module links";
            //return false;
          }

          moduleInfoArray = (ModuleInfo*)malloc(sizeof(ModuleInfo) * moduleInfoCount);

          // for each module
          for (uint32_t moduleIndex = 0; moduleIndex < moduleInfoCount; ++moduleIndex) {
            int modulesLACount = 0;
            ListAnnotation* modulesLAArray = nullptr;
            int modulesSACount = 0;
            SimpleAnnotation* modulesSAArray = nullptr;
            ModuleInfo moduleInfo {};

            if (dump.swap()) {
              Swap(&module_crashpad_info_links[moduleIndex].minidump_module_list_index);
              Swap(&module_crashpad_info_links[moduleIndex].location);
            }
            uint32_t minidump_module_list_index = module_crashpad_info_links[moduleIndex].minidump_module_list_index;

            if (!dump.SeekSet(module_crashpad_info_links[moduleIndex].location.rva)) {
              BPLOG(ERROR)
                  << "getMinidumpMetadata cannot seek to Crashpad module info";
              //return false;
            }

            MDRawModuleCrashpadInfo module_crashpad_info;
            if (!dump.ReadBytes(&module_crashpad_info,
                                      sizeof(module_crashpad_info))) {
              BPLOG(ERROR) << "getMinidumpMetadata cannot read Crashpad module info";
              //return false;
            }

            if (dump.swap()) {
              Swap(&module_crashpad_info.version);
              Swap(&module_crashpad_info.list_annotations);
              Swap(&module_crashpad_info.simple_annotations);
            }

            std::vector<std::string> list_annotations;
            if (module_crashpad_info.list_annotations.data_size) {
              if (dump.ReadStringList(
                      module_crashpad_info.list_annotations.rva,
                      &list_annotations)) {
                modulesLACount = list_annotations.size();
                modulesLAArray = (ListAnnotation*)malloc(sizeof(ListAnnotation) * modulesLACount);
                if (!modulesLAArray) {
                  // TODO
                }
                int laIndex = 0;
                for (std::vector<std::string>::const_iterator iterator = list_annotations.begin();
                    iterator != list_annotations.end();
                    ++iterator) {
                  ListAnnotation listAnnotation = {.value = duplicate((*iterator).c_str())};
                  BPLOG(ERROR) << "listAnnotation: value - " << listAnnotation.value;
                  modulesLAArray[laIndex] = listAnnotation;

                  ++laIndex;
                }
              } else {
                BPLOG(ERROR) << "getMinidumpMetadata cannot read Crashpad module "
                    "info list annotations";
                //return false;
              }
            }

            std::map<std::string, std::string> simple_annotations;
            if (module_crashpad_info.simple_annotations.data_size) {
              if (dump.ReadSimpleStringDictionary(
                      module_crashpad_info.simple_annotations.rva,
                      &simple_annotations)) {
                modulesSACount = simple_annotations_.size();
                modulesSAArray = (SimpleAnnotation*)malloc(sizeof(SimpleAnnotation) * modulesSACount);
                if (!modulesSAArray) {
                  // TODO
                }
                int saIndex = 0;
                for (std::map<std::string, std::string>::const_iterator iterator = simple_annotations_.begin();
                    iterator != simple_annotations_.end();
                    ++iterator) {
                  SimpleAnnotation simpleAnnotation = {.key = duplicate(iterator->first.c_str()), .value = duplicate(iterator->second.c_str())};
                  BPLOG(ERROR) << "simpleAnnotation: key - " << simpleAnnotation.key << " value - " << simpleAnnotation.value;
                  modulesSAArray[saIndex] = simpleAnnotation;

                  ++saIndex;
                }
              } else {
                BPLOG(ERROR) << "getMinidumpMetadata cannot read Crashpad module "
                    "info simple annotations";
                //return false;
              }
            }

            const MinidumpModule* module = module_list->GetModuleAtIndex(minidump_module_list_index);
            if (!module) {
              throw std::runtime_error("Bad module index");
            }

            //string debug_identifier = module->debug_identifier();
            //module_ids[i] = duplicate(debug_identifier);

            string code_file = PathnameStripper::File(module->code_file());

            //ModuleInfo moduleInfo = {.moduleName = duplicate(code_file), .listAnnotationCount = modulesLACount, .listAnnotations = modulesLAArray,
            //  .simpleAnnotationCount = modulesSACount, .simpleAnnotations = modulesSAArray};
            moduleInfo.moduleName = duplicate(code_file);
            moduleInfo.listAnnotations = modulesLAArray;
            moduleInfo.listAnnotationCount = modulesLACount;
            moduleInfo.simpleAnnotations = modulesSAArray;
            moduleInfo.simpleAnnotationCount = modulesSACount;

            moduleInfoArray[moduleIndex] = moduleInfo;

            // add to list of modules here?

            //result.moduleDetails.moduleCount = module_list->module_count();

            //const MinidumpModule* mainModule = module_list->GetMainModule();
            //if (!mainModule) {
            //  throw std::runtime_error("failed to get main module");
            //}
            //string mainModuleId = mainModule->debug_identifier();
            //result.moduleDetails.mainModuleId = duplicate(mainModuleId);

            //char** module_ids =
            //    (char**)malloc(sizeof(char*) * module_list->module_count());
            //if (!module_ids) {
            //  throw std::bad_alloc();
            //}
            //char** module_names =
            //    (char**)malloc(sizeof(char*) * module_list->module_count());
            //if (!module_names) {
            //  throw std::bad_alloc();
            //}

            /*
            for (unsigned int i = 0; i < module_list->module_count(); i++) {
              const MinidumpModule* module = module_list->GetModuleAtIndex(i);
              if (!module) {
                throw std::runtime_error("Bad module index");
              }

              string debug_identifier = module->debug_identifier();
              module_ids[i] = duplicate(debug_identifier);

              string code_file = PathnameStripper::File(module->code_file());
              string debug_file = PathnameStripper::File(module->debug_file());
              module_names[i] = duplicate(debug_file);
            }*/

            /*
            module_crashpad_info_links_.push_back(
                module_crashpad_info_links[index].minidump_module_list_index);
            module_crashpad_info_.push_back(module_crashpad_info);
            module_crashpad_info_list_annotations_.push_back(list_annotations);
            module_crashpad_info_simple_annotations_.push_back(simple_annotations);
            */
          }
        }

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        /*
        for (uint32_t module_index = 0;
              module_index < module_crashpad_info_links_.size();
              ++module_index) {
            printf("  module_list[%d].minidump_module_list_index = %d\n",
                  module_index, module_crashpad_info_links_[module_index]);
            printf("  module_list[%d].version = %d\n",
                  module_index, module_crashpad_info_[module_index].version);
            for (uint32_t annotation_index = 0;
                annotation_index <
                    module_crashpad_info_list_annotations_[module_index].size();
                ++annotation_index) {
              printf("  module_list[%d].list_annotations[%d] = %s\n",
                    module_index,
                    annotation_index,
                    module_crashpad_info_list_annotations_
                        [module_index][annotation_index].c_str());
            }
            for (std::map<std::string, std::string>::const_iterator iterator =
                    module_crashpad_info_simple_annotations_[module_index].begin();
                iterator !=
                    module_crashpad_info_simple_annotations_[module_index].end();
                ++iterator) {
              printf("  module_list[%d].simple_annotations[\"%s\"] = %s\n",
                    module_index, iterator->first.c_str(), iterator->second.c_str());
            }
          }
          */
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/*
const char* moduleName;
  int listAnnotationCount;
  ListAnnotation* listAnnotations;
  int simpleAnnotationCount;
  SimpleAnnotation* simpleAnnotations;
 */

        CrashpadInfo crashpadInfo = {.reportId = duplicate(MDGUIDToString(rawCrashpadInfo->report_id)), 
          .clientId = duplicate(MDGUIDToString(rawCrashpadInfo->client_id)),
          .simpleAnnotationCount = saCount,
          .simpleAnnotations = sa_array,
          .moduleCount = (int)moduleInfoCount,
          .moduleInfo = moduleInfoArray};

        MinidumpMetadata minidumpMetadata = {.crashpadInfo = crashpadInfo};

        return minidumpMetadata;
      }
  }
  
  return MinidumpMetadata {};
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
    result.event.metadata = getMinidumpMetadata(dump);

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
