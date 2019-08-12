cmake_minimum_required( VERSION 3.9 )

project(
    breakpad
    LANGUAGES C CXX
    VERSION 0.1
)

option( ${PROJECT_NAME}_PROCESSOR "Build processor library" ON )
option( ${PROJECT_NAME}_TOOLS "Build tool binaries" ON )
# NOTE: SELFTEST option not yet implemented

include( GNUInstallDirs )
include( CheckIncludeFile )



# ============================================================================
#
# Common includes and defines
#

include_directories( ${CMAKE_CURRENT_SOURCE_DIR}/src )
set( CMAKE_INCLUDE_CURRENT_DIR ON )

# Force CXX-11
set( CMAKE_CXX_STANDARD 11 )
set( CMAKE_CXX_STANDARD_REQUIRED ON )

add_definitions(
    -DPACKAGE_NAME=${PROJECT_NAME}
    -DPACKAGE_TARNAME=${PROJECT_NAME}
    -DPACKAGE_VERSION=${PROJECT_VERSION}
    -DPACKAGE_STRING="${PROJECT_NAME} ${PROJECT_VERSION}"
    -DPACKAGE_BUGREPORT=google-breakpad-dev@googlegroups.com
    -DPACKAGE_URL=
    -DVERSION=${PROJECT_VERSION}
    -DHAVE_CXX11
)



# ============================================================================
#
# Configure for local system
#

# find_package( GTest CONFIG REQUIRED )  # for SELFTEST

find_library( libdl dl )
if ( NOT libdl )
    message( FATAL_ERROR "Library not found: dl" )
endif()

if ( CMAKE_SYSTEM_PROCESSOR MATCHES "x86|X86|amd64|AMD64" )
    set( X86_HOST TRUE )
else ()
    set( X86_HOST FALSE )
endif ()

check_include_file( a.out.h HAVE_A_OUT_H )
if( HAVE_A_OUT_H )
    add_definitions( -DHAVE_A_OUT_H )
endif()

check_include_file( inttypes.h HAVE_INTTYPES_H )
if( HAVE_INTTYPES_H )
    add_definitions( -DHAVE_INTTYPES_H )
endif()

check_include_file( memory.h HAVE_MEMORY_H )
if( HAVE_MEMORY_H )
    add_definitions( -DHAVE_MEMORY_H )
endif()

set( THREADS_PREFER_PTHREAD_FLAG 1 )
include( FindThreads )
if ( CMAKE_USE_PTHREADS_INIT )
    add_definitions( -DHAVE_PTHREAD )
else()
    message( FATAL_ERROR "PThreads not found" )
endif()

check_include_file( stdint.h HAVE_STDINT_H )
if( HAVE_STDINT_H )
    add_definitions( -DHAVE_STDINT_H )
endif()

check_include_file( stdlib.h HAVE_STDLIB_H )
if( HAVE_STDLIB_H )
    add_definitions( -DHAVE_STDLIB_H )
endif()

check_include_file( strings.h HAVE_STRINGS_H )
if( HAVE_STRINGS_H )
    add_definitions( -DHAVE_STRINGS_H )
endif()

check_include_file( string.h HAVE_STRING_H )
if( HAVE_STRING_H )
    add_definitions( -DHAVE_STRING_H )
endif()

check_include_file( sys/random.h HAVE_SYS_RANDOM_H )
if( HAVE_SYS_RANDOM_H )
    add_definitions( -DHAVE_SYS_RANDOM_H )
endif()

check_include_file( sys/stat.h HAVE_SYS_STAT_H )
if( HAVE_SYS_STAT_H )
    add_definitions( -DHAVE_SYS_STAT_H )
endif()

check_include_file( sys/types.h HAVE_SYS_TYPES_H )
if( HAVE_SYS_TYPES_H )
    add_definitions( -DHAVE_SYS_TYPES_H )
endif()

check_include_file( unistd.h HAVE_UNISTD_H )
if( HAVE_UNISTD_H )
    add_definitions( -DHAVE_UNISTD_H )
endif()



# ============================================================================

if ( ${CMAKE_HOST_SYSTEM_NAME} STREQUAL "Linux" )

    # Define where headers get installed

    set( includeclh_HEADERS
        src/client/linux/handler/exception_handler.h
        src/client/linux/handler/microdump_extra_info.h
        src/client/linux/handler/minidump_descriptor.h
    )

    install(
        FILES ${includeclh_HEADERS}
        DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME}/client/linux/handler"
    )


    set( includecldwc_HEADERS
        src/client/linux/dump_writer_common/mapping_info.h
        src/client/linux/dump_writer_common/raw_context_cpu.h
        src/client/linux/dump_writer_common/thread_info.h
        src/client/linux/dump_writer_common/ucontext_reader.h
    )

    install(
        FILES ${includecldwc_HEADERS}
        DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME}/client/linux/dump_writer_common"
    )


    set( includeclm_HEADERS
        src/client/linux/minidump_writer/cpu_set.h
        src/client/linux/minidump_writer/directory_reader.h
        src/client/linux/minidump_writer/line_reader.h
        src/client/linux/minidump_writer/linux_core_dumper.h
        src/client/linux/minidump_writer/linux_dumper.h
        src/client/linux/minidump_writer/linux_ptrace_dumper.h
        src/client/linux/minidump_writer/minidump_writer.h
        src/client/linux/minidump_writer/minidump_writer_unittest_utils.h
        src/client/linux/minidump_writer/proc_cpuinfo_reader.h
    )

    install(
        FILES ${includeclm_HEADERS}
        DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME}/client/linux/minidump_writer"
    )


    set( includeclc_HEADERS
        src/client/linux/crash_generation/client_info.h
        src/client/linux/crash_generation/crash_generation_client.h
        src/client/linux/crash_generation/crash_generation_server.h
    )

    install(
        FILES ${includeclc_HEADERS}
        DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME}/client/linux/crash_generation"
    )


    set( includelss_HEADERS
        src/third_party/lss/linux_syscall_support.h
    )

    install(
        FILES ${includelss_HEADERS}
        DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME}/third_party/lss"
    )


    set( includecl_HEADERS
        src/common/linux/crc32.h
        src/common/linux/dump_symbols.h
        src/common/linux/eintr_wrapper.h
        src/common/linux/elf_core_dump.h
        src/common/linux/elf_gnu_compat.h
        src/common/linux/elf_symbols_to_module.h
        src/common/linux/elfutils.h
        src/common/linux/elfutils-inl.h
        src/common/linux/file_id.h
        src/common/linux/google_crashdump_uploader.h
        src/common/linux/guid_creator.h
        src/common/linux/http_upload.h
        src/common/linux/ignore_ret.h
        src/common/linux/libcurl_wrapper.h
        src/common/linux/linux_libc_support.h
        src/common/linux/memory_mapped_file.h
        src/common/linux/safe_readlink.h
        src/common/linux/symbol_upload.h
        src/common/linux/synth_elf.h
    )

    install(
        FILES ${includecl_HEADERS}
        DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME}/common/linux"
    )



    # libbreakpad_client.a

    set( libbreakpad_client_a_SOURCES
        src/client/linux/crash_generation/crash_generation_client.cc
        src/client/linux/crash_generation/crash_generation_server.cc
        src/client/linux/dump_writer_common/thread_info.cc
        src/client/linux/dump_writer_common/ucontext_reader.cc
        src/client/linux/handler/exception_handler.cc
        src/client/linux/handler/exception_handler.h
        src/client/linux/handler/minidump_descriptor.cc
        src/client/linux/handler/minidump_descriptor.h
        src/client/linux/log/log.cc
        src/client/linux/log/log.h
        src/client/linux/microdump_writer/microdump_writer.cc
        src/client/linux/microdump_writer/microdump_writer.h
        src/client/linux/minidump_writer/linux_core_dumper.cc
        src/client/linux/minidump_writer/linux_dumper.cc
        src/client/linux/minidump_writer/linux_ptrace_dumper.cc
        src/client/linux/minidump_writer/minidump_writer.cc
        src/client/minidump_file_writer-inl.h
        src/client/minidump_file_writer.cc
        src/client/minidump_file_writer.h
        src/common/convert_UTF.c
        src/common/convert_UTF.h
        src/common/md5.cc
        src/common/md5.h
        src/common/string_conversion.cc
        src/common/string_conversion.h
        src/common/linux/elf_core_dump.cc
        src/common/linux/elfutils.cc
        src/common/linux/elfutils.h
        src/common/linux/file_id.cc
        src/common/linux/file_id.h
        src/common/linux/guid_creator.cc
        src/common/linux/guid_creator.h
        src/common/linux/linux_libc_support.cc
        src/common/linux/memory_mapped_file.cc
        src/common/linux/safe_readlink.cc
    )

    add_library(
        breakpad_client STATIC ${libbreakpad_client_a_SOURCES}
    )

    set_target_properties( breakpad_client
        PROPERTIES
            EXPORT_NAME               breakpad_client
            OUTPUT_NAME               breakpad_client
            VERSION                   ${PROJECT_VERSION}
            POSITION_INDEPENDENT_CODE ON
    )

    target_include_directories( breakpad_client
        PUBLIC
            "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME}>"
    )
    target_link_libraries( breakpad_client ${CMAKE_THREAD_LIBS_INIT} )

    install(
        TARGETS breakpad_client
        EXPORT  ${PROJECT_NAME}-targets
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    )


    if ( ${PROJECT_NAME}_TOOLS )

        # core2md

        add_executable( core2md
            src/tools/linux/core2md/core2md.cc
        )

        target_link_libraries( core2md breakpad_client )
        install(
            TARGETS core2md
            EXPORT  ${PROJECT_NAME}-targets
            RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        )


        # dump_syms

        add_executable( dump_syms
            src/tools/linux/dump_syms/dump_syms.cc
            src/common/dwarf_cfi_to_module.cc
            src/common/dwarf_cu_to_module.cc
            src/common/dwarf_line_to_module.cc
            src/common/dwarf_range_list_handler.cc
            src/common/language.cc
            src/common/module.cc
            src/common/path_helper.cc
            src/common/stabs_reader.cc
            src/common/stabs_to_module.cc
            src/common/dwarf/bytereader.cc
            src/common/dwarf/dwarf2diehandler.cc
            src/common/dwarf/dwarf2reader.cc
            src/common/dwarf/elf_reader.cc
            src/common/linux/crc32.cc
            src/common/linux/dump_symbols.cc
            src/common/linux/dump_symbols.h
            src/common/linux/elf_symbols_to_module.cc
            src/common/linux/elf_symbols_to_module.h
            src/common/linux/elfutils.cc
            src/common/linux/file_id.cc
            src/common/linux/linux_libc_support.cc
            src/common/linux/memory_mapped_file.cc
            src/common/linux/safe_readlink.cc
        )

        target_link_libraries( dump_syms ${libdl} ${CMAKE_THREAD_LIBS_INIT} )
        install(
            TARGETS dump_syms
            EXPORT  ${PROJECT_NAME}-targets
            RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        )


        # minidump-2-core

        add_executable( minidump-2-core
            src/common/linux/memory_mapped_file.cc
            src/common/path_helper.cc
            src/tools/linux/md2core/minidump-2-core.cc
            src/tools/linux/md2core/minidump_memory_range.h
        )

        install(
            TARGETS minidump-2-core
            EXPORT  ${PROJECT_NAME}-targets
            RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        )


        # minidump_upload

        add_executable( minidump_upload
            src/common/linux/http_upload.cc
            src/tools/linux/symupload/minidump_upload.cc
        )

        target_link_libraries( minidump_upload ${libdl} )
        install(
            TARGETS minidump_upload
            EXPORT  ${PROJECT_NAME}-targets
            RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        )


        # sym_upload

        add_executable( sym_upload
            src/common/linux/http_upload.cc
            src/common/linux/http_upload.h
            src/common/linux/symbol_upload.cc
            src/common/linux/symbol_upload.h
            src/tools/linux/symupload/sym_upload.cc
        )

        target_link_libraries( sym_upload ${libdl} )
        install(
            TARGETS sym_upload
            EXPORT  ${PROJECT_NAME}-targets
            RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        )


        if ( ${X86_HOST} )

            # dump_syms_mac

            add_executable( dump_syms_mac
                src/common/dwarf_cfi_to_module.cc
                src/common/dwarf_cu_to_module.cc
                src/common/dwarf_line_to_module.cc
                src/common/dwarf_range_list_handler.cc
                src/common/language.cc
                src/common/md5.cc
                src/common/module.cc
                src/common/path_helper.cc
                src/common/stabs_reader.cc
                src/common/stabs_to_module.cc
                src/common/dwarf/bytereader.cc
                src/common/dwarf/dwarf2diehandler.cc
                src/common/dwarf/dwarf2reader.cc
                src/common/dwarf/elf_reader.cc
                src/common/mac/arch_utilities.cc
                src/common/mac/dump_syms.cc
                src/common/mac/dump_syms.h
                src/common/mac/file_id.cc
                src/common/mac/file_id.h
                src/common/mac/macho_id.cc
                src/common/mac/macho_id.h
                src/common/mac/macho_reader.cc
                src/common/mac/macho_reader.h
                src/common/mac/macho_utilities.cc
                src/common/mac/macho_utilities.h
                src/common/mac/macho_walker.cc
                src/common/mac/macho_walker.h
                src/tools/mac/dump_syms/dump_syms_tool.cc
            )

            target_include_directories( dump_syms_mac PUBLIC "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/third_party/mac_headers>" )
            target_compile_definitions( dump_syms_mac PRIVATE -DHAVE_MACH_O_NLIST_H )
            install(
                TARGETS dump_syms_mac
                EXPORT  ${PROJECT_NAME}-targets
                RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
            )

        endif()

    endif() # option TOOLS

endif() # Linux


set( includegbc_HEADERS
    src/google_breakpad/common/breakpad_types.h
    src/google_breakpad/common/minidump_cpu_amd64.h
    src/google_breakpad/common/minidump_cpu_arm64.h
    src/google_breakpad/common/minidump_cpu_arm.h
    src/google_breakpad/common/minidump_cpu_mips.h
    src/google_breakpad/common/minidump_cpu_ppc64.h
    src/google_breakpad/common/minidump_cpu_ppc.h
    src/google_breakpad/common/minidump_cpu_sparc.h
    src/google_breakpad/common/minidump_cpu_x86.h
    src/google_breakpad/common/minidump_exception_fuchsia.h
    src/google_breakpad/common/minidump_exception_linux.h
    src/google_breakpad/common/minidump_exception_mac.h
    src/google_breakpad/common/minidump_exception_ps3.h
    src/google_breakpad/common/minidump_exception_solaris.h
    src/google_breakpad/common/minidump_exception_win32.h
    src/google_breakpad/common/minidump_format.h
    src/google_breakpad/common/minidump_size.h
)

install(
    FILES ${includegbc_HEADERS}
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME}/google_breakpad/common"
)

set( includec_HEADERS
    src/common/basictypes.h
    src/common/byte_cursor.h
    src/common/convert_UTF.h
    src/common/dwarf_cfi_to_module.h
    src/common/dwarf_cu_to_module.h
    src/common/dwarf_line_to_module.h
    src/common/dwarf_range_list_handler.h
    src/common/language.h
    src/common/long_string_dictionary.h
    src/common/md5.h
    src/common/memory_allocator.h
    src/common/memory_range.h
    src/common/minidump_type_helper.h
    src/common/module.h
    src/common/path_helper.h
    src/common/scoped_ptr.h
    src/common/simple_string_dictionary.h
    src/common/stabs_reader.h
    src/common/stabs_to_module.h
    src/common/stdio_wrapper.h
    src/common/string_conversion.h
    src/common/symbol_data.h
    src/common/test_assembler.h
    src/common/unordered.h
    src/common/using_std_string.h
)

install(
    FILES ${includec_HEADERS}
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME}/common"
)

set( includep_HEADERS
    src/processor/address_map.h
    src/processor/address_map-inl.h
    src/processor/basic_code_module.h
    src/processor/basic_code_modules.h
    src/processor/basic_source_line_resolver_types.h
    src/processor/cfi_frame_info.h
    src/processor/cfi_frame_info-inl.h
    src/processor/contained_range_map.h
    src/processor/contained_range_map-inl.h
    src/processor/convert_old_arm64_context.h
    src/processor/disassembler_x86.h
    src/processor/exploitability_linux.h
    src/processor/exploitability_win.h
    src/processor/fast_source_line_resolver_types.h
    src/processor/linked_ptr.h
    src/processor/logging.h
    src/processor/map_serializers.h
    src/processor/map_serializers-inl.h
    src/processor/module_comparer.h
    src/processor/module_factory.h
    src/processor/module_serializer.h
    src/processor/pathname_stripper.h
    src/processor/postfix_evaluator.h
    src/processor/postfix_evaluator-inl.h
    src/processor/range_map.h
    src/processor/range_map-inl.h
    src/processor/simple_serializer.h
    src/processor/simple_serializer-inl.h
    src/processor/simple_symbol_supplier.h
    src/processor/source_line_resolver_base_types.h
    src/processor/stackwalk_common.h
    src/processor/stackwalker_address_list.h
    src/processor/stackwalker_amd64.h
    src/processor/stackwalker_arm64.h
    src/processor/stackwalker_arm.h
    src/processor/stackwalker_mips.h
    src/processor/stackwalker_ppc64.h
    src/processor/stackwalker_ppc.h
    src/processor/stackwalker_sparc.h
    src/processor/stackwalker_unittest_utils.h
    src/processor/stackwalker_x86.h
    src/processor/static_address_map.h
    src/processor/static_address_map-inl.h
    src/processor/static_contained_range_map.h
    src/processor/static_contained_range_map-inl.h
    src/processor/static_map.h
    src/processor/static_map-inl.h
    src/processor/static_map_iterator.h
    src/processor/static_map_iterator-inl.h
    src/processor/static_range_map.h
    src/processor/static_range_map-inl.h
    src/processor/symbolic_constants_win.h
    src/processor/synth_minidump.h
    src/processor/synth_minidump_unittest_data.h
    src/processor/tokenize.h
    src/processor/windows_frame_info.h
)

install(
    FILES ${includep_HEADERS}
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME}/processor"
)



if ( ${PROJECT_NAME}_PROCESSOR )

    # libbreakpad.a

    set( libbreakpad_a_SOURCES
        src/google_breakpad/common/breakpad_types.h
        src/google_breakpad/common/minidump_format.h
        src/google_breakpad/common/minidump_size.h
        src/google_breakpad/processor/basic_source_line_resolver.h
        src/google_breakpad/processor/call_stack.h
        src/google_breakpad/processor/code_module.h
        src/google_breakpad/processor/code_modules.h
        src/google_breakpad/processor/dump_context.h
        src/google_breakpad/processor/dump_object.h
        src/google_breakpad/processor/exploitability.h
        src/google_breakpad/processor/fast_source_line_resolver.h
        src/google_breakpad/processor/memory_region.h
        src/google_breakpad/processor/microdump.h
        src/google_breakpad/processor/microdump_processor.h
        src/google_breakpad/processor/minidump.h
        src/google_breakpad/processor/minidump_processor.h
        src/google_breakpad/processor/process_result.h
        src/google_breakpad/processor/process_state.h
        src/google_breakpad/processor/proc_maps_linux.h
        src/google_breakpad/processor/source_line_resolver_base.h
        src/google_breakpad/processor/source_line_resolver_interface.h
        src/google_breakpad/processor/stack_frame.h
        src/google_breakpad/processor/stack_frame_cpu.h
        src/google_breakpad/processor/stack_frame_symbolizer.h
        src/google_breakpad/processor/stackwalker.h
        src/google_breakpad/processor/symbol_supplier.h
        src/google_breakpad/processor/system_info.h
        src/processor/address_map-inl.h
        src/processor/address_map.h
        src/processor/basic_code_module.h
        src/processor/basic_code_modules.cc
        src/processor/basic_code_modules.h
        src/processor/basic_source_line_resolver_types.h
        src/processor/basic_source_line_resolver.cc
        src/processor/call_stack.cc
        src/processor/cfi_frame_info.cc
        src/processor/cfi_frame_info.h
        src/processor/contained_range_map-inl.h
        src/processor/contained_range_map.h
        src/processor/convert_old_arm64_context.cc
        src/processor/convert_old_arm64_context.h
        src/processor/disassembler_x86.h
        src/processor/disassembler_x86.cc
        src/processor/dump_context.cc
        src/processor/dump_object.cc
        src/processor/exploitability.cc
        src/processor/exploitability_linux.h
        src/processor/exploitability_linux.cc
        src/processor/exploitability_win.h
        src/processor/exploitability_win.cc
        src/processor/fast_source_line_resolver_types.h
        src/processor/fast_source_line_resolver.cc
        src/processor/linked_ptr.h
        src/processor/logging.h
        src/processor/logging.cc
        src/processor/map_serializers-inl.h
        src/processor/map_serializers.h
        src/processor/microdump.cc
        src/processor/microdump_processor.cc
        src/processor/minidump.cc
        src/processor/minidump_processor.cc
        src/processor/module_comparer.cc
        src/processor/module_comparer.h
        src/processor/module_factory.h
        src/processor/module_serializer.cc
        src/processor/module_serializer.h
        src/processor/pathname_stripper.cc
        src/processor/pathname_stripper.h
        src/processor/postfix_evaluator-inl.h
        src/processor/postfix_evaluator.h
        src/processor/process_state.cc
        src/processor/proc_maps_linux.cc
        src/processor/range_map-inl.h
        src/processor/range_map.h
        src/processor/simple_serializer-inl.h
        src/processor/simple_serializer.h
        src/processor/simple_symbol_supplier.cc
        src/processor/simple_symbol_supplier.h
        src/processor/windows_frame_info.h
        src/processor/source_line_resolver_base_types.h
        src/processor/source_line_resolver_base.cc
        src/processor/stack_frame_cpu.cc
        src/processor/stack_frame_symbolizer.cc
        src/processor/stackwalker.cc
        src/processor/stackwalker_amd64.cc
        src/processor/stackwalker_amd64.h
        src/processor/stackwalker_arm.cc
        src/processor/stackwalker_arm.h
        src/processor/stackwalker_arm64.cc
        src/processor/stackwalker_arm64.h
        src/processor/stackwalker_address_list.cc
        src/processor/stackwalker_address_list.h
        src/processor/stackwalker_mips.cc
        src/processor/stackwalker_mips.h
        src/processor/stackwalker_ppc.cc
        src/processor/stackwalker_ppc.h
        src/processor/stackwalker_ppc64.cc
        src/processor/stackwalker_ppc64.h
        src/processor/stackwalker_sparc.cc
        src/processor/stackwalker_sparc.h
        src/processor/stackwalker_x86.cc
        src/processor/stackwalker_x86.h
        src/processor/static_address_map-inl.h
        src/processor/static_address_map.h
        src/processor/static_contained_range_map-inl.h
        src/processor/static_contained_range_map.h
        src/processor/static_map_iterator-inl.h
        src/processor/static_map_iterator.h
        src/processor/static_map-inl.h
        src/processor/static_map.h
        src/processor/static_range_map-inl.h
        src/processor/static_range_map.h
        src/processor/symbolic_constants_win.cc
        src/processor/symbolic_constants_win.h
        src/processor/tokenize.cc
        src/processor/tokenize.h
    )

    add_library(
        breakpad STATIC ${libbreakpad_a_SOURCES}
    )

    set_target_properties( breakpad
        PROPERTIES
            EXPORT_NAME               breakpad
            OUTPUT_NAME               breakpad
            VERSION                   ${PROJECT_VERSION}
            POSITION_INDEPENDENT_CODE ON
    )

    target_include_directories( breakpad PUBLIC "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME}>" )
    target_link_libraries( breakpad ${CMAKE_THREAD_LIBS_INIT} )

    install(
        TARGETS breakpad
        EXPORT  ${PROJECT_NAME}-targets
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    )


    # libdisasm.a -- not installed; for build targets only

    set( libdisasm_a_SOURCES
        src/third_party/libdisasm/ia32_implicit.c
        src/third_party/libdisasm/ia32_implicit.h
        src/third_party/libdisasm/ia32_insn.c
        src/third_party/libdisasm/ia32_insn.h
        src/third_party/libdisasm/ia32_invariant.c
        src/third_party/libdisasm/ia32_invariant.h
        src/third_party/libdisasm/ia32_modrm.c
        src/third_party/libdisasm/ia32_modrm.h
        src/third_party/libdisasm/ia32_opcode_tables.c
        src/third_party/libdisasm/ia32_opcode_tables.h
        src/third_party/libdisasm/ia32_operand.c
        src/third_party/libdisasm/ia32_operand.h
        src/third_party/libdisasm/ia32_reg.c
        src/third_party/libdisasm/ia32_reg.h
        src/third_party/libdisasm/ia32_settings.c
        src/third_party/libdisasm/ia32_settings.h
        src/third_party/libdisasm/libdis.h
        src/third_party/libdisasm/qword.h
        src/third_party/libdisasm/x86_disasm.c
        src/third_party/libdisasm/x86_format.c
        src/third_party/libdisasm/x86_imm.c
        src/third_party/libdisasm/x86_imm.h
        src/third_party/libdisasm/x86_insn.c
        src/third_party/libdisasm/x86_misc.c
        src/third_party/libdisasm/x86_operand_list.c
        src/third_party/libdisasm/x86_operand_list.h
    )

    add_library(
        disasm STATIC ${libdisasm_a_SOURCES}
    )

    set_target_properties( disasm
        PROPERTIES
            POSITION_INDEPENDENT_CODE ON
    )


    # microdump_stackwalk

    add_executable( microdump_stackwalk
        src/processor/microdump_stackwalk.cc
        src/common/path_helper.cc
        src/processor/stackwalk_common.cc
    )

    target_link_libraries( microdump_stackwalk breakpad disasm )
    install(
        TARGETS microdump_stackwalk
        EXPORT  ${PROJECT_NAME}-targets
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )


    # minidump_dump

    add_executable( minidump_dump
        src/processor/minidump_dump.cc
    )

    target_link_libraries( minidump_dump breakpad disasm )
    install(
        TARGETS minidump_dump
        EXPORT  ${PROJECT_NAME}-targets
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )


    # minidump_stackwalk

    add_executable( minidump_stackwalk
        src/processor/minidump_stackwalk.cc
        src/common/path_helper.cc
        src/processor/stackwalk_common.cc
    )

    target_link_libraries( minidump_stackwalk breakpad disasm )
    install(
        TARGETS minidump_stackwalk
        EXPORT  ${PROJECT_NAME}-targets
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )

endif() # option PROCESSOR


if ( ${PROJECT_NAME}_PROCESSOR OR ${CMAKE_HOST_SYSTEM_NAME} STREQUAL "Linux" )

    include( CMakePackageConfigHelpers )

    file( WRITE "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake.in"
        "@PACKAGE_INIT@\ninclude( \${CMAKE_CURRENT_LIST_DIR}/${PROJECT_NAME}Targets.cmake )" )

    configure_package_config_file(
        "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake.in"
        "${PROJECT_NAME}Config.cmake"
        INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}
        PATH_VARS           CMAKE_INSTALL_LIBDIR
    )

    write_basic_package_version_file(
        "${PROJECT_NAME}ConfigVersion.cmake"
        VERSION       ${PROJECT_VERSION}
        COMPATIBILITY SameMajorVersion
    )

    install(
        FILES
            ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake
            ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}
    )

    install(
        EXPORT ${PROJECT_NAME}-targets
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}"
        FILE ${PROJECT_NAME}Targets.cmake
    )

endif()

install(
    FILES
        AUTHORS
        ChangeLog
        INSTALL
        LICENSE
        NEWS
        README.md
    DESTINATION "${CMAKE_INSTALL_DATAROOTDIR}/doc/${PROJECT_NAME}-${PROJECT_VERSION}"
)


# ============================================================================
#
# Packaging
# https://cmake.org/cmake/help/latest/module/CPack.html
#

set( CPACK_PACKAGE_NAME ${PROJECT_NAME} )
set( CPACK_PACKAGE_VENDOR "Google" )
set( CPACK_PACKAGE_DESCRIPTION_SUMMARY "An open-source multi-platform crash reporting system" )
set( CPACK_PACKAGE_HOMEPAGE_URL "https://chromium.googlesource.com/breakpad/breakpad" )
set( CPACK_PACKAGE_CONTACT      "${PACKAGE_BUGREPORT}" )
set( CPACK_PACKAGE_VERSION ${PROJECT_VERSION} )
set( CPACK_PACKAGE_INSTALL_DIRECTORY ${PROJECT_NAME} )
set( CPACK_RESOURCE_FILE_LICENSE "${CMAKE_SOURCE_DIR}/LICENSE" )
set( CPACK_RESOURCE_FILE_README "${CMAKE_CURRENT_SOURCE_DIR}/README.md" )

if(${CMAKE_SYSTEM_NAME} STREQUAL "Linux")

    if ( "${CPACK_PACKAGE_ARCHITECTURE}" STREQUAL "" )
        # Note: the architecture should default to the local architecture, but it
        # in fact comes up empty.  We call `uname -m` to ask the kernel instead.
        EXECUTE_PROCESS( COMMAND uname -m COMMAND tr -d '\n' OUTPUT_VARIABLE CPACK_PACKAGE_ARCHITECTURE )
    endif()

    set( CPACK_INCLUDE_TOPLEVEL_DIRECTORY 1 )
    set( CPACK_PACKAGE_RELEASE 1 )


    # RPM - https://cmake.org/cmake/help/latest/cpack_gen/rpm.html
    set( CPACK_RPM_PACKAGE_RELEASE ${CPACK_PACKAGE_RELEASE} )
    set( CPACK_RPM_PACKAGE_ARCHITECTURE ${CPACK_PACKAGE_ARCHITECTURE} )
    set( CPACK_RPM_PACKAGE_DESCRIPTION ${CPACK_PACKAGE_DESCRIPTION_SUMMARY} )
    set( CPACK_RPM_PACKAGE_URL ${CPACK_PACKAGE_HOMEPAGE_URL} )
    set( CPACK_RPM_PACKAGE_LICENSE "BSD-3-Clause" )
    set( CPACK_RPM_COMPONENT_INSTALL 0 )
    set( CPACK_RPM_COMPRESSION_TYPE "xz" )
    set( CPACK_RPM_PACKAGE_AUTOPROV 1 )
    set( CPACK_RPM_PACKAGE_NAME "${CPACK_PACKAGE_NAME}-devel" )
    set( CPACK_RPM_FILE_NAME
         "${CPACK_RPM_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-${CPACK_RPM_PACKAGE_RELEASE}.${CPACK_RPM_PACKAGE_ARCHITECTURE}.rpm" )

    # DEB - https://cmake.org/cmake/help/latest/cpack_gen/deb.html
    set( CPACK_DEBIAN_PACKAGE_RELEASE ${CPACK_PACKAGE_RELEASE} )
    set( CPACK_DEBIAN_PACKAGE_HOMEPAGE ${CPACK_PACKAGE_HOMEPAGE_URL} )
    set( CPACK_DEB_COMPONENT_INSTALL 0 )
    set( CPACK_DEBIAN_COMPRESSION_TYPE "xz")

    if ( ${CPACK_PACKAGE_ARCHITECTURE} STREQUAL "x86_64" )
        set( CPACK_DEBIAN_PACKAGE_ARCHITECTURE "amd64" )  # DEB doesn't always use the kernel's arch name
    else()
        set( CPACK_DEBIAN_PACKAGE_ARCHITECTURE ${CPACK_PACKAGE_ARCHITECTURE} )
    endif()

    set( CPACK_DEBIAN_FILE_NAME "DEB-DEFAULT" ) # Use default naming scheme
    set( CPACK_DEBIAN_PACKAGE_NAME "${CPACK_PACKAGE_NAME}-dev" )

elseif( ${CMAKE_HOST_WIN32} )
    set( CPACK_NSIS_ENABLE_UNINSTALL_BEFORE_INSTALL ON )
    set( CPACK_NSIS_DISPLAY_NAME ${PROJECT_NAME} )
    set( CPACK_NSIS_PACKAGE_NAME ${PROJECT_NAME} )
    set( CPACK_NSIS_URL_INFO_ABOUT ${CPACK_PROJECT_HOMEPAGE_URL} )
endif()


# This must always be last!
include( CPack )
