SET(target tipc_config)
SET(srcs
	tipc_config.c)
SET(includes 
	${ROOT_DIR}/open_source/tipc/src/include)

SET(deps securec)


SET(custom_define -DVERSION=\"UNKNOWN\")
SET(custom_macro -Wno-format-nonliteral -D_FORTIFY_SOURCE=2)
if(($ENV{CPU_INSX} STREQUAL "arm_cortexa9le") OR ($ENV{CPU_INSX} STREQUAL "arm_cortexa15le") OR ($ENV{CPU_INSX} STREQUAL "arm_cortexa53le"))
	list(APPEND custom_define -DVFP_CPU_INSA_ARM32)
elseif(($ENV{CPU_INSX} STREQUAL "arm_cortexa72le") OR ($ENV{CPU_INSX} STREQUAL "arm64"))
	list(APPEND custom_define -DVFP_CPU_INSA_ARM64)
elseif($ENV{CPU_INSX} STREQUAL "mips")
	list(APPEND custom_define -DVFP_CPU_INSA_MIPS)
elseif(($ENV{CPU_INSX} STREQUAL "ppc") OR ($ENV{CPU_INSX} STREQUAL "ppc_rtos"))
	list(APPEND custom_define -DVFP_CPU_INSA_PPC)
elseif($ENV{CPU_INSX} STREQUAL "ppc_e500v2")
	list(APPEND custom_define -DVFP_CPU_INSA_PPC_E500V2)
elseif($ENV{CPU_INSX} STREQUAL "xlp8xx")
	list(APPEND custom_define -DVFP_CPU_INSA_XLP8XX)
endif()
SET(strip "--strip-unneeded")


hw_compile_bin(TARGET ${target} SRC ${srcs} INCLUDE ${includes} DEP ${deps} TARGET_COPY ${target_copy} CUSTOM_MACRO ${custom_macro} CUSTOM_DEFINE ${custom_define} STRIP_ARGS ${strip})
