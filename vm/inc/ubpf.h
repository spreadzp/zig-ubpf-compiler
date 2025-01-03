// Copyright (c) 2015 Big Switch Networks, Inc
// SPDX-License-Identifier: Apache-2.0

/*
 * Copyright 2015 Big Switch Networks, Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef UBPF_H
#define UBPF_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <ubpf_config.h>

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/**
 * @brief Default maximum number of instructions that a program can contain.
 */
#if !defined(UBPF_MAX_INSTS)
#define UBPF_MAX_INSTS 65536
#endif

/**
 * @brief Default maximum number of nested calls in the VM.
 */
#if !defined(UBPF_MAX_CALL_DEPTH)
#define UBPF_MAX_CALL_DEPTH 8
#endif

/**
 * @brief Default stack size for the eBPF program. Must be divisible by 16.
 */
#if !defined(UBPF_EBPF_STACK_SIZE)
#define UBPF_EBPF_STACK_SIZE (UBPF_MAX_CALL_DEPTH * 512)
#endif

/**
 * @brief Default stack size for each local eBPF function.
 *
 * The size of the stack for each local eBPF function multiplied
 * by the max call depth (\ref UBPF_EBPF_STACK_SIZE) must be
 * less than or equal to the total stack size for the eBPF VM
 * (\ref UBPF_EBPF_STACK_SIZE).
 */
#if !defined(UBPF_EBPF_LOCAL_FUNCTION_STACK_SIZE)
#define UBPF_EBPF_LOCAL_FUNCTION_STACK_SIZE 256
#endif

#define UBPF_EBPF_NONVOLATILE_SIZE (sizeof(uint64_t) * 5)


    /**
     * @brief Opaque type for a the uBPF VM.
     */
    struct ubpf_vm;

    /**
     * @brief Opaque type for a uBPF JIT compiled function.
     */
    typedef uint64_t (*ubpf_jit_fn)(void* mem, size_t mem_len);

    /**
     * @brief Opaque type for a uBPF JIT compiled function with
     *        external stack.
     */
    typedef uint64_t (*ubpf_jit_ex_fn)(void* mem, size_t mem_len, uint8_t* stack, size_t stack_len);

    /**
     * @brief Enum to describe JIT mode.
     *
     * ExtendedJitMode specifies that an invocation of that code have 4 parameters:
     * 1. A pointer to the program's memory space.
     * 2. The size of the program's memory space.
     * 3. A pointer to memory to be used by the program as a stack during execution.
     * 4. The size of the provided stack space.
     * See ubpf_jit_ex_fn for more information.
     *
     * BasicJitMode specifies that an invocation of that code have 2 parameters:
     * 1. A pointer to the program's memory space.
     * 2. The size of the program's memory space.
     * The function generated by the JITer executing in basic mode automatically
     * allocates a stack for the program's execution.
     * See ubpf_jit_fn for more information.
     */
    enum JitMode
    {
        ExtendedJitMode,
        BasicJitMode
    };

    /**
     * @brief Create a new uBPF VM.
     *
     * @return A pointer to the new VM, or NULL on failure.
     */
    struct ubpf_vm*
    ubpf_create(void);

    /**
     * @brief Free a uBPF VM.
     *
     * @param[in] vm The VM to free.
     */
    void
    ubpf_destroy(struct ubpf_vm* vm);

    /**
     * @brief Enable / disable bounds_check. Bounds check is enabled by default, but it may be too restrictive.
     *
     * @param[in] vm The VM to enable / disable bounds check on.
     * @param[in] enable Enable bounds check if true, disable if false.
     * @retval true Bounds check was previously enabled.
     */
    bool
    ubpf_toggle_bounds_check(struct ubpf_vm* vm, bool enable);

    /**
     * @brief Set the function to be invoked if the program hits a fatal error.
     *
     * @param[in] vm The VM to set the error function on.
     * @param[in] error_printf The function to be invoked on fatal error.
     */
    void
    ubpf_set_error_print(struct ubpf_vm* vm, int (*error_printf)(FILE* stream, const char* format, ...));

    /**
     * @brief The type of an external helper function.
     *
     * Note: There is an implicit <tt>void *</tt>-typed 6th parameter that users can access if they choose. That
     * sixth parameter's value is the value of the pointer given by the user of \ref ubpf_exec, \ref ubpf_exec_ex, and
     * the function generated by \ref ubpf_translate as the first argument.
     */
    typedef uint64_t (*external_function_t)(uint64_t p0, uint64_t p1, uint64_t p2, uint64_t p3, uint64_t p4);

    /**
     * @brief Cast an external function to \ref external_function_t
     *
     * Some external functions may not use all the parameters (or may use the implicit
     * 6th parameter) and, therefore, not match the \ref external_function_t typedef.
     * Use this for a conversion.
     *
     * @param[in] f The function to cast to match the signature of an
     *              external function.
     * @retval The external function, as external_function_t.
     */
    external_function_t
    as_external_function_t(void* f);

    /**
     * @brief Register an external function.
     * The immediate field of a CALL instruction is an index into an array of
     * functions registered by the user. This API associates a function with
     * an index.
     *
     * @param[in] vm The VM to register the function on.
     * @param[in] index The index to register the function at.
     * @param[in] name The human readable name of the function.
     * @param[in] fn The function to register.
     * @retval 0 Success.
     * @retval -1 Failure.
     */
    int
    ubpf_register(struct ubpf_vm* vm, unsigned int index, const char* name, external_function_t fn);

    /**
     * @brief The type of an external helper dispatcher function.
     */
    typedef uint64_t (*external_function_dispatcher_t)(
        uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, unsigned int index, void* cookie);

    /**
     * @brief The type of an external helper validation function.
     */
    typedef bool (*external_function_validate_t)(unsigned int index, const struct ubpf_vm* vm);

    /**
     * @brief Register a function that dispatches to external helpers
     * The immediate field of a CALL instruction is an index of a helper
     * function to invoke. This API sets a callback that will choose the
     * helper function to invoke (based on the index) and then invoke it.
     * This API also sets a callback that the validator will use to determine
     * if a given index is a valid external function.
     *
     * @param[in] vm The VM to register the function on.
     * @param[in] dispatcher The callback that will dispatch to the external
     *                       helper.
     * @param[in] validater The callback that will validate that a given index
     *                      is valid for an external helper.
     * @retval 0 Success.
     * @retval -1 Failure.
     */
    int
    ubpf_register_external_dispatcher(
        struct ubpf_vm* vm, external_function_dispatcher_t dispatcher, external_function_validate_t validater);

    /**
     * @brief The type of a stack usage calculator callback function.
     *
     * See ubpf_register_stack_usage_calculator for additional information.
     */
    typedef int (*stack_usage_calculator_t)(const struct ubpf_vm* vm, uint16_t pc, void* cookie);

    /**
     * @brief Register a function that will be called during eBPF program validation
     * to determine stack usage for a local function.
     *
     * In eBPF, the frame pointer is a read-only register. Therefore, the eBPF interpreter
     * or the eBPF JITer need to know the stack usage for each local function so that the
     * frame pointer can be adjusted properly on behalf of the calling function. The callback
     * registered here has access to a cookie for context (specified in the call to this function),
     * the PC (in the eBPF program) of the first instruction of a local function and the `ubpf_vm`.
     *
     * The callback's job is to calculate the amount of stack space used by the local function that
     * starts at the given PC.
     *
     * If the callback returns 0 or there is no callback registered, the eBPF interpreter/JITer
     * assume that the local function uses the maximum stack available according to the spec (512K).
     *
     * @param[in] vm The VM to register the callback with.
     * @param[in] dispatcher The callback that will be invoked to determine the amount of stack
     *                       usage for a local function that starts at ...
     * @param[in] pc The pc of the function whose stack usage the callback must caculate.
     * @retval 0 Success.
     * @retval -1 Failure.
     */
    int
    ubpf_register_stack_usage_calculator(struct ubpf_vm* vm, stack_usage_calculator_t calculator, void* cookie);

    /**
     * @brief Load code into a VM.
     * This must be done before calling ubpf_exec or ubpf_compile and after
     * registering all functions.
     *
     * 'code' should point to eBPF bytecodes and 'code_len' should be the size in
     * bytes of that buffer.
     *
     * @param[in] vm The VM to load the code into.
     * @param[in] code The eBPF bytecodes to load.
     * @param[in] code_len The length of the eBPF bytecodes.
     * @param[out] errmsg The error message, if any. This should be freed by the caller.
     * @retval 0 Success.
     * @retval -1 Failure.
     */
    int
    ubpf_load(struct ubpf_vm* vm, const void* code, uint32_t code_len, char** errmsg);

    /*
     * Unload code from a VM
     *
     * This must be done before calling ubpf_load or ubpf_load_elf, except for the
     * first time those functions are called. It clears the VM instructions to
     * allow for new code to be loaded.
     *
     * It does not unregister any external functions.
     */

    /**
     * @brief Unload code from a VM.
     *
     * The VM must be reloaded with code before calling ubpf_exec or ubpf_compile.
     *
     * @param[in] vm The VM to unload the code from.
     */
    void
    ubpf_unload_code(struct ubpf_vm* vm);

#if defined(UBPF_HAS_ELF_H)
    /**
     * @brief Load code from an ELF file.

     * This must be done before calling ubpf_exec or ubpf_compile and after
     * registering all functions.
     *
     * 'elf' should point to a copy of an ELF file in memory and 'elf_len' should
     * be the size in bytes of that buffer.
     *
     * The ELF file must be 64-bit little-endian with a single text section
     * containing the eBPF bytecodes. This is compatible with the output of
     * Clang.
     *
     * @param[in] vm The VM to load the code into.
     * @param[in] elf A pointer to a copy of an ELF file in memory.
     * @param[in] elf_len The size of the ELF file.
     * @param[out] errmsg The error message, if any. This should be freed by the caller.
     * @retval 0 Success.
     * @retval -1 Failure.
     */
    int
    ubpf_load_elf(struct ubpf_vm* vm, const void* elf, size_t elf_len, char** errmsg);

    /**
     * @brief Load code from an ELF file with extra parameters for extended control.

     * This must be done before calling ubpf_exec or ubpf_compile and after
     * registering all functions.
     *
     * 'elf' should point to a copy of an ELF file in memory and 'elf_len' should
     * be the size in bytes of that buffer.
     *
     * The ELF file must be 64-bit little-endian with a single text section
     * containing the eBPF bytecodes. This is compatible with the output of
     * Clang.
     *
     * @param[in] vm The VM to load the code into.
     * @param[in] elf A pointer to a copy of an ELF file in memory.
     * @param[in] elf_len The size of the ELF file.
     * @param[in] main_function_name The name of the eBPF program's main function.
     *            execution will start here.
     * @param[out] errmsg The error message, if any. This should be freed by the caller.
     * @retval 0 Success.
     * @retval -1 Failure.
     */
    int
    ubpf_load_elf_ex(struct ubpf_vm* vm, const void* elf, size_t elf_len, const char* main_section_name, char** errmsg);
#endif

    /**
     * @brief Execute a BPF program in the VM using the interpreter.
     *
     * A program must be loaded into the VM and all external functions must be
     * registered before calling this function.
     *
     * @param[in] vm The VM to execute the program in.
     * @param[in] mem The memory to pass to the program.
     * @param[in] mem_len The length of the memory.
     * @param[in] bpf_return_value The value of the r0 register when the program exits.
     * @retval 0 Success.
     * @retval -1 Failure.
     */
    int
    ubpf_exec(const struct ubpf_vm* vm, void* mem, size_t mem_len, uint64_t* bpf_return_value);

    int
    ubpf_exec_ex(
        const struct ubpf_vm* vm,
        void* mem,
        size_t mem_len,
        uint64_t* bpf_return_value,
        uint8_t* stack,
        size_t stack_len);

    /**
     * @brief Compile a BPF program in the VM to native code.
     *
     * A program must be loaded into the VM and all external functions (or
     * the external helper dispatcher) must be registered before calling this
     * function.
     *
     * The JITer executes in basic mode when invoked through this function.
     *
     * @param[in] vm The VM to compile the program in.
     * @param[out] errmsg The error message, if any. This should be freed by the caller.
     * @return A pointer to the compiled program, or NULL on failure.
     */
    ubpf_jit_fn
    ubpf_compile(struct ubpf_vm* vm, char** errmsg);

    /**
     * @brief Compile a BPF program in the VM to native code.
     *
     * A program must be loaded into the VM and all external functions (or
     * the external helper dispatcher) must be registered before calling this
     * function.
     *
     * The JITer executes in the prescribed mode when invoked through this function.
     * If jit_mode is basic, the caller will have to cast the function pointer to the
     * appropriate type (ubpf_jit_fn).
     *
     * @param[in] vm The VM to compile the program in.
     * @param[out] errmsg The error message, if any. This should be freed by the caller.
     * @param[in] jit_mode The mode in which to execute the JITer -- basic or extended.
     * @return A pointer to the compiled program, or NULL on failure.
     */
    ubpf_jit_ex_fn
    ubpf_compile_ex(struct ubpf_vm* vm, char** errmsg, enum JitMode jit_mode);

    /**
     * @brief Copy the JIT'd program code to the given buffer.
     *
     * A program must have been loaded into the VM and already JIT'd before
     * calling this function.
     *
     * Note: Caller must know the mode in which the JITer was executed and may
     * need to cast the result to the appropriate type (e.g., ubpf_jit_ex_fn).
     *
     * @param[in] vm The VM of the already JIT'd program.
     * @param[out] errmsg The error message, if any. This should be freed by the caller.
     * @return A pointer to the compiled program (the same as buffer), or
     *         NULL on failure.
     */
    ubpf_jit_fn
    ubpf_copy_jit(struct ubpf_vm* vm, void* buffer, size_t size, char** errmsg);

    /**
     * @brief Translate the eBPF byte code to machine code.
     *
     * A program must be loaded into the VM and all external functions must be
     * registered before calling this function.
     *
     * The JITer executes in basic mode when invoked through this function.
     *
     * @param[in] vm The VM to translate the program in.
     * @param[out] buffer The buffer to store the translated code in.
     * @param[in] size The size of the buffer.
     * @param[out] errmsg The error message, if any. This should be freed by the caller.
     * @retval 0 Success.
     * @retval -1 Failure.
     */
    int
    ubpf_translate(struct ubpf_vm* vm, uint8_t* buffer, size_t* size, char** errmsg);

    /**
     * @brief Translate the eBPF byte code to machine code.
     *
     * A program must be loaded into the VM and all external functions must be
     * registered before calling this function.
     *
     * The JITer executes in the prescribed mode when invoked through this function.
     *
     * @param[in] vm The VM to translate the program in.
     * @param[out] buffer The buffer to store the translated code in.
     * @param[in] size The size of the buffer.
     * @param[out] errmsg The error message, if any. This should be freed by the caller.
     * @param[in] jit_mode The mode in which to execute the JITer -- basic or extended.
     * @retval 0 Success.
     * @retval -1 Failure.
     */
    int
    ubpf_translate_ex(struct ubpf_vm* vm, uint8_t* buffer, size_t* size, char** errmsg, enum JitMode jit_mode);

    /**
     * @brief Instruct the uBPF runtime to apply unwind-on-success semantics to a helper function.
     * If the function returns 0, the uBPF runtime will end execution of
     * the eBPF program and immediately return control to the caller. This is used
     * for implementing function like the "bpf_tail_call" helper.
     *
     * @param[in] vm The VM to set the unwind helper in.
     * @param[in] idx Index of the helper function to unwind on success.
     * @retval 0 Success.
     * @retval -1 Failure.
     */
    int
    ubpf_set_unwind_function_index(struct ubpf_vm* vm, unsigned int idx);

    /**
     * @brief Override the storage location for the BPF registers in the VM.
     *
     * @param[in] vm The VM to set the register storage in.
     * @param[in] regs The register storage.
     */
    void
    ubpf_set_registers(struct ubpf_vm* vm, uint64_t* regs);

    /**
     * @brief Retrieve the storage location for the BPF registers in the VM.
     *
     * @param[in] vm The VM to get the register storage from.
     * @return A pointer to the register storage.
     */
    uint64_t*
    ubpf_get_registers(const struct ubpf_vm* vm);

    /**
     * @brief Optional secret to improve ROP protection.
     *
     * @param[in] vm The VM to set the secret for.
     * @param[in] secret Optional secret to improve ROP protection.
     * Returns 0 on success, -1 on error (e.g. if the secret is set after
     * the instructions are loaded).
     */
    int
    ubpf_set_pointer_secret(struct ubpf_vm* vm, uint64_t secret);

    /**
     * @brief Data relocation function that is called by the VM when it encounters a
     * R_BPF_64_64 relocation in the maps section of the ELF file.
     *
     * @param[in] user_context The user context that was passed to ubpf_register_data_relocation.
     * @param[in] data Pointer to start of the map section.
     * @param[in] data_size Size of the map section.
     * @param[in] symbol_name Name of the symbol that is referenced.
     * @param[in] symbol_offset Offset of the symbol relative to the start of the map section.
     * @param[in] symbol_size Size of the symbol.
     * @return The value to insert into the BPF program.
     */
    typedef uint64_t (*ubpf_data_relocation)(
        void* user_context,
        const uint8_t* data,
        uint64_t data_size,
        const char* symbol_name,
        uint64_t symbol_offset,
        uint64_t symbol_size);

    /**
     * @brief Set a relocation function for the VM.
     *
     * @param[in] vm The VM to set the relocation function for.
     * @param[in] relocation The relocation function.
     * @return The value to insert into the BPF program.
     */
    int
    ubpf_register_data_relocation(struct ubpf_vm* vm, void* user_context, ubpf_data_relocation relocation);

    /**
     * @brief Function that is called by the VM to check if a memory access is within bounds.
     *
     * @param[in] context The user context that was passed to ubpf_register_data_bounds_check.
     * @param[in] addr The address to check.
     * @param[in] size The size of the memory access.
     * @retval True The memory access is within bounds.
     * @retval False The memory access is out of bounds.
     */
    typedef bool (*ubpf_bounds_check)(void* context, uint64_t addr, uint64_t size);

    /**
     * @brief Set a bounds check function for the VM.
     *
     * @param[in] vm The VM to set the bounds check function for.
     * @param[in] user_context The user context to pass to the bounds check function.
     * @param[in] bounds_check The bounds check function.
     * @retval 0 Success.
     * @retval -1 Failure.
     */
    int
    ubpf_register_data_bounds_check(struct ubpf_vm* vm, void* user_context, ubpf_bounds_check bounds_check);

    /**
     * @brief Set a size for the buffer allocated to machine code generated during JIT compilation.
     * The JIT compiler allocates a buffer to store the code while it is being generated. The default
     * may be too big for some embedded platforms. Use this to customize the size of that buffer.
     * Note: The buffer being sized here is *not* the final location of the machine code returned by
     * ubpf_compile -- that buffer is perfectly sized to match the size of the generated machine code.
     *
     * @param[in] vm The VM to set the buffer size for.
     * @param[in] code_size The size of the buffer to use.
     * @retval 0 Success.
     * @retval -1 Failure.
     */
    int
    ubpf_set_jit_code_size(struct ubpf_vm* vm, size_t code_size);

    /**
     * @brief Set the instruction limit for the VM. This is the maximum number
     * of instructions that a program may execute during a call to ubpf_exec.
     * It has no effect on JIT'd programs.
     *
     * @param[in] vm The VM to set the instruction limit for.
     * @param[in] limit The maximum number of instructions that a program may execute or 0 for no limit.
     * @param[out] previous_limit Optional pointer to store the previous instruction limit.
     * @retval 0 Success.
     * @retval -1 Failure.
     */
    int
    ubpf_set_instruction_limit(struct ubpf_vm* vm, uint32_t limit, uint32_t* previous_limit);

    /**
     * @brief Enable or disable undefined behavior checks. Undefined behavior includes
     * reading from uninitialized memory or using uninitialized registers. Default is disabled to
     * preserve performance and compatibility with existing eBPF programs.
     *
     * @param[in] vm VM to enable or disable undefined behavior checks on.
     * @param[in] enable Enable undefined behavior checks if true, disable if false.
     * @retval true Undefined behavior checks were previously enabled.
     * @retval false Undefined behavior checks were previously disabled.
     */
    bool
    ubpf_toggle_undefined_behavior_check(struct ubpf_vm* vm, bool enable);

    /**
     * @brief A function to invoke before each instruction.
     *
     * @param[in, out] context Context passed in to ubpf_register_debug_fn.
     * @param[in] program_counter Current instruction pointer.
     * @param[in] registers Array of 11 registers representing the VM state.
     * @param[in] stack_start Pointer to the beginning of the stack.
     * @param[in] stack_length Size of the stack in bytes.
     * @param[in] register_mask Bitmask of registers that have been modified since the start of the program.
     *  Each set bit represents 1 modified register. LSB corresponds to register 0 and so on.
     * @param[in] stack_mask_start Bitmask of the stack that has been modified since the start of the program.
     *  Each set bit represents 1 byte of the stack that has been modified. LSB corresponds to the first byte relative
     * to stack_start and the MSB corresponds to the last byte. Note that the stack grows downwards, so the byte
     * corresponding to the MSB is the first byte of the stack from the POV of the program and LSB is the last byte.
     */
    typedef void (*ubpf_debug_fn)(
        void* context,
        int program_counter,
        const uint64_t registers[16],
        const uint8_t* stack_start,
        size_t stack_length,
        uint64_t register_mask,
        const uint8_t* stack_mask_start);

    /**
     * @brief Add option to invoke a debug function before each instruction.
     * Note: This only applies to the interpreter and not the JIT.
     *
     * @param[in] vm VM to add the option to.
     * @param[in] debug_fn Function to invoke before each instruction. Pass NULL to remove the function.
     * @retval 0 Success.
     * @retval -1 Failure.
     */
    int
    ubpf_register_debug_fn(struct ubpf_vm* vm, void* context, ubpf_debug_fn debug_function);
#ifdef __cplusplus
}
#endif

#endif