// Copyright 2010 Google LLC
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//     * Neither the name of Google LLC nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// Original author: Jim Blandy <jimb@mozilla.com> <jimb@red-bean.com>

// language.cc: Subclasses and singletons for google_breakpad::Language.
// See language.h for details.

#ifdef HAVE_CONFIG_H
#include <config.h>  // Must come first
#endif

#include "common/language.h"

#include <stdlib.h>
#include <array>

#if !defined(__ANDROID__)
#include <cxxabi.h>
#endif

#if defined(HAVE_RUSTC_DEMANGLE)
#include <rustc_demangle.h>
#endif

#include <limits>

namespace {

// Annotates a variable indicating that its storage should not be filled with a
// fixed pattern when uninitialized.
//
// The `init_stack_vars` gn arg (enabled on most build configs) causes the
// compiler to generate code that writes a fixed pattern into uninitialized
// parts of all local variables, to mitigate security risks. In most cases, e.g.
// when such memory is either never accessed or will be initialized later before
// reading, the compiler is able to remove the additional stores, and any
// remaining stores are unlikely to affect program performance.
//
// If hot code suffers unavoidable perf penalties, this can disable the
// pattern-filling there. This should only be done when necessary, since reads
// from uninitialized variables are not only UB, they can in practice allow
// attackers to control logic by pre-filling the variable's memory with a
// desirable value.
#if __has_cpp_attribute(clang::uninitialized)
#define STACK_UNINITIALIZED [[clang::uninitialized]]
#elif __has_cpp_attribute(gnu::uninitialized)
#define STACK_UNINITIALIZED [[gnu::uninitialized]]
#else
#define STACK_UNINITIALIZED
#endif

std::string MakeQualifiedNameWithSeparator(const std::string& parent_name,
                                           const char* separator,
                                           const std::string& name) {
  if (parent_name.empty()) {
    return name;
  }

  return parent_name + separator + name;
}

bool IsObjectiveCMethod(const std::string& name) {
  return name.size() >= 2 && (name[0] == '-' || name[0] == '+') &&
         name[1] == '[';
}

}  // namespace

namespace google_breakpad {

// C++ language-specific operations.
class CPPLanguage: public Language {
 public:
  CPPLanguage() {}

  std::string MakeQualifiedName(const std::string& parent_name,
                                const std::string& name) const {
    return MakeQualifiedNameWithSeparator(parent_name, "::", name);
  }

  virtual DemangleResult DemangleName(const std::string& mangled,
                                      std::string* demangled) const {
#if defined(__ANDROID__)
    // Android NDK doesn't provide abi::__cxa_demangle.
    demangled->clear();
    return kDontDemangle;
#else
    // Attempting to demangle non-C++ symbols with the C++ demangler would print
    // warnings and fail, so return kDontDemangle for these.
    if (!IsMangledName(mangled)) {
      demangled->clear();
      return kDontDemangle;
    }

    int status;
    char* demangled_c =
        abi::__cxa_demangle(mangled.c_str(), nullptr, nullptr, &status);

    DemangleResult result;
    if (status == 0) {
      result = kDemangleSuccess;
      demangled->assign(demangled_c);
    } else {
      result = kDemangleFailure;
      demangled->clear();
    }

    if (demangled_c) {
      free(reinterpret_cast<void*>(demangled_c));
    }

    return result;
#endif
  }

 private:
  static bool IsMangledName(const std::string& name) {
    // NOTE: For proper cross-compilation support, this should depend on target
    // binary's platform, not current build platform.
#if defined(__APPLE__)
    // Mac C++ symbols can have up to 4 underscores, followed by a "Z".
    // Non-C++ symbols are not coded that way, but may have leading underscores.
    size_t i = name.find_first_not_of('_');
    return i > 0 && i != std::string::npos && i <= 4 && name[i] == 'Z';
#else
    // Linux C++ symbols always start with "_Z".
    return name.size() > 2 && name[0] == '_' && name[1] == 'Z';
#endif
  }
};

CPPLanguage CPPLanguageSingleton;

// Objective-C language-specific operations.
class ObjectiveCLanguage: public Language {
 public:
  ObjectiveCLanguage() {}

  std::string MakeQualifiedName(const std::string& parent_name,
                                const std::string& name) const {
    // In Objective-C, names are not qualified. Objective-C methods are already
    // fully qualified as `-[Class method]` or `+[Class method]`.
    return name;
  }
};

ObjectiveCLanguage ObjectiveCLanguageSingleton;

// Objective-C++ language-specific operations.
class ObjectiveCPlusPlusLanguage: public CPPLanguage {
 public:
  ObjectiveCPlusPlusLanguage() {}

  std::string MakeQualifiedName(const std::string& parent_name,
                                const std::string& name) const {
    // Starting with DWARF v5, clang/LLVM emits Objective-C method
    // declarations nested inside the class/interface type's structure
    // block. When processing these declarations, dump_syms retrieves
    // the parent class name as the enclosing scope.
    //
    // Since Objective-C method names are already fully qualified
    // (e.g., `-[Class method]`), we should not qualify them with
    // C++ `::` prefixes.
    if (IsObjectiveCMethod(name)) {
      return name;
    }
    return MakeQualifiedNameWithSeparator(parent_name, "::", name);
  }
};

ObjectiveCPlusPlusLanguage ObjectiveCPlusPlusLanguageSingleton;

// Java language-specific operations.
class JavaLanguage: public Language {
 public:
  JavaLanguage() {}

  std::string MakeQualifiedName(const std::string& parent_name,
                                const std::string& name) const {
    return MakeQualifiedNameWithSeparator(parent_name, ".", name);
  }
};

JavaLanguage JavaLanguageSingleton;

// Swift language-specific operations.
class SwiftLanguage: public Language {
 public:
  SwiftLanguage() {}

  std::string MakeQualifiedName(const std::string& parent_name,
                                const std::string& name) const {
    return MakeQualifiedNameWithSeparator(parent_name, ".", name);
  }

  virtual DemangleResult DemangleName(const std::string& mangled,
                                      std::string* demangled) const {
    // There is no programmatic interface to a Swift demangler. Pass through the
    // mangled form because it encodes more information than the qualified name
    // that would have been built by MakeQualifiedName(). The output can be
    // post-processed by xcrun swift-demangle to transform mangled Swift names
    // into something more readable.
    demangled->assign(mangled);
    return kDemangleSuccess;
  }
};

SwiftLanguage SwiftLanguageSingleton;

// Rust language-specific operations.
class RustLanguage: public Language {
 public:
  RustLanguage() {}

  std::string MakeQualifiedName(const std::string& parent_name,
                                const std::string& name) const {
    return MakeQualifiedNameWithSeparator(parent_name, ".", name);
  }

  virtual DemangleResult DemangleName(const std::string& mangled,
                                      std::string* demangled) const {
    // Rust names use GCC C++ name mangling, but demangling them with
    // abi_demangle doesn't produce stellar results due to them having
    // another layer of encoding.
    // If callers provide rustc-demangle, use that.
#if defined(HAVE_RUSTC_DEMANGLE)
    // DemangleName() is hot when dumping symbols, and profiling on a Linux
    // Chrome build showed that automatic initialization of this 1 MiB buffer
    // took ~6.8% of user CPU cycles because the compiler cannot optimize it out
    // across the call to rustc_demangle(). Safe because rustc_demangle()
    // NUL-terminates the buffer on success before it is read.
    STACK_UNINITIALIZED std::array<char, 1 * 1024 * 1024> rustc_demangled;
    if (rustc_demangle(mangled.c_str(), rustc_demangled.data(),
                       rustc_demangled.size()) == 0) {
      return kDemangleFailure;
    }
    demangled->assign(rustc_demangled.data());
#else
    // Otherwise, pass through the mangled name so callers can demangle
    // after the fact.
    demangled->assign(mangled);
#endif
    return kDemangleSuccess;
  }
};

RustLanguage RustLanguageSingleton;

// Assembler language-specific operations.
class AssemblerLanguage: public Language {
 public:
  AssemblerLanguage() {}

  bool HasFunctions() const { return false; }
  std::string MakeQualifiedName(const std::string& parent_name,
                                const std::string& name) const {
    return name;
  }
};

AssemblerLanguage AssemblerLanguageSingleton;

const Language * const Language::CPlusPlus = &CPPLanguageSingleton;
const Language * const Language::Java = &JavaLanguageSingleton;
const Language * const Language::Swift = &SwiftLanguageSingleton;
const Language * const Language::Rust = &RustLanguageSingleton;
const Language * const Language::Assembler = &AssemblerLanguageSingleton;
const Language * const Language::ObjectiveC = &ObjectiveCLanguageSingleton;
const Language * const Language::ObjectiveCPlusPlus =
    &ObjectiveCPlusPlusLanguageSingleton;

} // namespace google_breakpad
