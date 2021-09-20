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

typedef struct RegisterValue {
  const char* name;
  const char* value;
} RegisterValue;

typedef struct Register {
  int frameIndex;
  int registerValueCount;
  RegisterValue* registerValues;
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

typedef struct SimpleAnnotation {
  const char* key;
  const char* value;
} SimpleAnnotation;

typedef struct ListAnnotation {
  const char* value;
} ListAnnotation;

typedef struct ModuleInfo {
  const char* moduleName;
  int listAnnotationCount;
  ListAnnotation* listAnnotations;
  int simpleAnnotationCount;
  SimpleAnnotation* simpleAnnotations;
} ModuleInfo;

typedef struct CrashpadInfo {
  const char* reportId;
  const char* clientId;
  int simpleAnnotationCount;
  SimpleAnnotation* simpleAnnotations;
  int moduleCount;
  ModuleInfo* moduleInfo;
} CrashpadInfo;

typedef struct MinidumpMetadata {
  CrashpadInfo crashpadInfo;
  const char* assertion;
} MinidumpMetadata;

typedef struct Event {
  int threadCount;
  const char* temp;
  Exception exception;
  App app;
  Device device;
  Thread* threads;
  MinidumpMetadata metaData;
  bool unhandled;
} Event;

typedef struct ModuleDetails {
  int moduleCount;
  char* mainModuleId;
  char** moduleIds;
  char** moduleNames;
  char** moduleCodeFiles;
} ModuleDetails;

typedef struct WrappedEvent {
  Event event;
  const char* pstrErr;
} WrappedEvent;

typedef struct WrappedModuleDetails {
  ModuleDetails moduleDetails;
  const char* pstrErr;
} WrappedModuleDetails;

typedef struct SerializedModuleDetails {
  const char* code_file;
  const char* module_path;
  unsigned int serialized_size;
  char* serialized_data;
} SerializedModuleDetails;

WrappedModuleDetails GetModuleDetails(const char* minidump_filename);
bool SerializeModule(SerializedModuleDetails* stack_module_details);
WrappedEvent GetEventFromMinidump(const char* filename,
                                  const int stack_details_size,
                                  SerializedModuleDetails** stack_details);
void DestroyEvent(WrappedEvent* wrapped_event);
void DestroyModuleDetails(WrappedModuleDetails* wrapped_module_details);
void DestroySerializedModuleDetails(SerializedModuleDetails* serialized_module_details);

#ifdef __cplusplus
}
#endif

#endif  // STACKWALK_WRAPPER_H
