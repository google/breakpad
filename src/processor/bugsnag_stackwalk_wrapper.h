#ifndef STACKWALK_WRAPPER_H
#define STACKWALK_WRAPPER_H

#include <string.h>
#include <string>
#include <vector>

#ifdef __cplusplus
extern "C" {
#endif

  typedef struct Stackframe {
    const char* filename;
    const char* method;
    const char* frameAddress;
    const char* moduleId;
    const char* moduleName;

    void destroy() {
      // TODO ensure that it is not null first (in all of the destroy functions)
      free((void *)filename);
      free((void *)method);
      free((void *)frameAddress);
      free((void *)moduleId);
      free((void *)moduleName);
    }
  } Stackframe;

  typedef struct Stacktrace {
    int frameCount;
    Stackframe* frames;

    void destroy() {
      free(frames);
    }
  } Stacktrace;

  typedef struct Exception {
    Stacktrace stacktrace;
    const char* errorClass;

    void destroy() {
      free((void *)errorClass);
      stacktrace.destroy();
    }
  } Exception;

  typedef struct App {
    int duration;
    const char* binaryArch;
  
    void destroy() {
      free((void *)binaryArch);
    }
  } App;

  typedef struct Device {
    const char* osName;
    const char* osVersion;

    void destroy() {
      free((void *)osName);
      free((void *)osVersion);
    }
  } Device;

  typedef struct Event {
    const char* temp;
    Exception exception;
    App app;
    Device device;

    void destroy() {
      app.destroy();
      device.destroy();
    }
  } Event;

  typedef struct ModuleDetails {
    int moduleCount;
    char** moduleIds;
    char** moduleNames;

    void destroy() {
      for (int i = 0; i < moduleCount; i++) {
        free((void *)moduleIds[i]);
        free((void *)moduleNames[i]);
      }
      free((void *)moduleIds);
      free((void *)moduleNames);
    }
  } ModuleDetails;

  ModuleDetails GetModuleDetails(const char* minidump_filename);
  Event GetEventFromMinidump(const char* filename, const char* symbol_path);
  void FreeEvent(Event* event);
  void FreeModuleDetails(ModuleDetails* module_details);

#ifdef __cplusplus
}
#endif

#endif
