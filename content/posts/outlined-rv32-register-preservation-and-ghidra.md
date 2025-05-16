+++
title = "Aside: Outlined RISCV-32 Register Preservation and Ghidra"
date = "2025-05-16T01:16:27Z"
author = "Irate-Walrus"
cover = ""
tags = ["RISC-V", "Ghidra", "RE"]
keywords = ["RISC-V", "Ghidra", "Reverse Engineering"]
readingTime = true
+++

I somewhat recently stumbled upon a somewhat annoying pattern while traversing a RISCV-32 program. It looked just a little like this in the _Listing_:

```c
	     **************************************************************
	     *                          FUNCTION                          *
	     **************************************************************
	     undefined example_fn()
undefined         <UNASSIGNED>   <RETURN>
	     example                                    
ef b2 86 fb     jal        t0,prologue_stub_t0                              void prologue_stub_t0(void)
			    <...SNIP...>
6f b0 86 f9     j          epilogue_stub_ret                                void epilogue_stub_ret(void)
```

And like this in the _Decompiler_:

```c
void example_fn(undefined1 *param_1,int param_2)

{
  int iVar1;
  undefined4 uVar1;
  undefined4 uVar2;

  iVar1 = prologue_stub_t0();
  
  uVar1 = 0x12;
  if (iVar1 == extraout_a1){
    uVar1 = 0x17;
  }
  
  uVar2 = epilogue_stub_ret(uVar1);
  return uVar2;
}
```

So where were these `jalr,` and `j` instructions going? To outlined callee-saved register preservation and restoration:

```c
**************************************************************
*                          FUNCTION                          *
**************************************************************
void __stdcall prologue_stub_t0(void)
  <VOID>         <RETURN>
  Stack[-0x10]:4 local_10  
prologue_stub_t0
    c.addi     sp,-0x10
    c.swsp     s2,0x0(sp=>local_10)
    c.swsp     s1,0x4(sp)
    c.swsp     s0,0x8(sp)
    c.swsp     ra,0xc(sp)
    c.jr       t0
```

Ghidra was treating these as a call and was therefore clobbering any registers that weren't saved between these "calls".

> Ghidra really hated `jalr` and `jal` calls in general, deciding that the majority of them never returned. It was easier just to disable this analyzer.

To somewhat resolve this, inline both the `prelude_stub_t0` and `epilogue_stub_ret` setting the _Calling Convention_ as `default`. Also mark the  `j epilogue_stub_ret` as `- Flow Override: RETURN (TERMINATOR)` using _Modify Instruction Flow->RETURN_ via the right-click context menu (or a script of your choice).

If you don't update the _Instruction Flow_ to `RETURN` you may experience somthing similar the following error:

*"Low-level Error: Could not find op at target address: (ram,0x8001200e)"*

I found this fixed the majority of cases, but not all, so slam your head against the wall as necessary.

If you have any better ways of dealing with this, I'd love to hear them.
