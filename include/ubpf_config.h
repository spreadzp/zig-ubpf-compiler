#ifndef UBPF_CONFIG_H
#define UBPF_CONFIG_H

/* Default configuration for uBPF */

#ifndef UBPF_MAX_INSTS
#define UBPF_MAX_INSTS 65536
#endif

#ifndef UBPF_MAX_CALL_DEPTH
#define UBPF_MAX_CALL_DEPTH 8
#endif

#ifndef UBPF_EBPF_STACK_SIZE
#define UBPF_EBPF_STACK_SIZE (UBPF_MAX_CALL_DEPTH * 512)
#endif

#ifndef UBPF_EBPF_LOCAL_FUNCTION_STACK_SIZE
#define UBPF_EBPF_LOCAL_FUNCTION_STACK_SIZE 256
#endif

/* Define if ELF support is available */
#define UBPF_HAS_ELF_H 1

#endif /* UBPF_CONFIG_H */