#ifndef STACKWALK_WRAPPER_H
#define STACKWALK_WRAPPER_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct Stackframe {
  const char* filename;
  const char* method;
  const char* frameAddress;
  const char* loadAddress;
  const char* moduleId;
  const char* moduleName;
  const char* returnAddress;
  const char* symbolAddress;
  const char* codeFile;
  const char* trust;
} Stackframe;

typedef struct Stacktrace {
  int frameCount;
  Stackframe* frames;
} Stacktrace;

typedef struct RegisterData {
  const char* registerName;
  const char* registerValue;
} RegisterData;

typedef struct Register {
  int frameIndex;
  int registerDataCount;
  RegisterData* registerDataItems;
} Register;

typedef struct Exception {
  Stacktrace stacktrace;
  const char* errorClass;
  const char* crashAddress;
  int registerCount;
  Register* registers;
} Exception;

typedef struct App {
  int duration;
  const char* binaryArch;
} App;

typedef struct Device {
  const char* osName;
  const char* osVersion;
} Device;

typedef struct Thread {
  int id;
  bool errorReportingThread;
  Stacktrace stacktrace;
} Thread;

typedef struct Event {
  int threadCount;
  const char* temp;
  Exception exception;
  App app;
  Device device;
  Thread* threads;
} Event;

typedef struct ModuleDetails {
  int moduleCount;
  char* mainModuleId;
  char** moduleIds;
  char** moduleNames;
} ModuleDetails;

typedef struct WrappedEvent {
  Event event;
  const char* pstrErr;
} WrappedEvent;

typedef struct WrappedModuleDetails {
  ModuleDetails moduleDetails;
  const char* pstrErr;
} WrappedModuleDetails;

WrappedModuleDetails GetModuleDetails(const char* minidump_filename);
WrappedEvent GetEventFromMinidump(const char* filename,
                                  const int symbol_path_count,
                                  const char** symbol_paths);
void DestroyEvent(WrappedEvent* wrapped_event);
void DestroyModuleDetails(WrappedModuleDetails* wrapped_module_details);

#ifdef __cplusplus
}
#endif

#endif  // STACKWALK_WRAPPER_H
