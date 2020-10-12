# CustomSyscall
Windows x64 driver to create a new syscall by injecting a new entry in KeServiceDescriptorTable's SST 

# How it works
Start by pattern search the whole `.text` section of the kernel for reference to KeServiceDescriptorTable (SSDT).
This table contains a System Service Table (SST) that contains offsets to all syscalls for ConsoleApplications (for non-GUI calling threads). The SST in question is a fixed length `PLONG` array. The structure of the SSDT is

```C
typedef LONG SYSTEM_SERVICE_TABLE, *PSYSTEM_SERVICE_TABLE;
typedef struct _KSERVICE_DESCRIPTOR_TABLE {
    PSYSTEM_SERVICE_TABLE ServiceTableBase;         // Pointer to the base of the SST
    PSYSTEM_SERVICE_TABLE ServiceCounterTableBase;  //
    ULONG NumberOfServices;                         // Number of elements in ServiceTableBase
    PUCHAR ParamTableBase;                          // Size of the stack arguments for each syscall
} KSERVICE_DESCRIPTOR_TABLE, *PKSERVICE_DESCRIPTOR_TABLE;
```

In memory the `ServiceTableBase` is labeled with non-exported symbol `KiServiceTable` and it's part of a fixed length structure. The structure is as follows:

```C
struct _SSDT {
    const LONG KiServiceTable[KiServiceLimit];
    const LONG KiServiceLimit;
    const BYTE KiArgumentTable[KiServiceLimit];
} SST;
```

To inject a custom syscall we need to modify `NumberOfServices` to a [number bigger than our custom syscall number](https://github.com/uafio/CustomSyscall/blob/main/CustomSyscall/main.cpp#L233). After that, we corrupt `KiServiceTable` by inserting our specially crafted value in [KiServiceTable[custom syscall]](https://github.com/uafio/CustomSyscall/blob/main/CustomSyscall/main.cpp#L232). As you can tell, we need to do a out-of-bounds write here to an offset that would overflow past the last entry of `KiArgumentTable` [plus some extra](https://github.com/uafio/CustomSyscall/blob/main/CustomSyscall/main.cpp#L178).

To craft the value to inject into the `KiServiceTable` we need to understand [how syscalls are resolved](#How-syscalls-are-resolved) from the `SSDT`. As you can see, all syscall functions need to be located ~256MB before or after the `KiServiceTable/ServiceTableBase`. Logically, our syscall will reside in our own driver, most likely not within the allowed address space. To handle that, we are going to [look for a code cave](https://github.com/uafio/CustomSyscall/blob/main/CustomSyscall/main.cpp#L97) somewhere in the kernel's .text section to hold a [trampoline to our syscall](https://github.com/uafio/CustomSyscall/blob/main/CustomSyscall/main.cpp#L223).


# How syscalls are resolved
When syscall is executed, the syscall number is considered an offset within the `SystemServiceTable`. Then the value at that offset is shifted right one nibble (4 bits) and added to the `SystemServiceTable` as so
```
Function = SystemServiceTable + (SystemServiceTable[sysnum] >> 4)
```

Let's resolve the `6th` syscall number.
```
1: kd> dq KeServiceDescriptorTable L4
fffff801`97437780  fffff801`9737e1c0 00000000`00000000
fffff801`97437790  00000000`000001c2 fffff801`9737e8cc

1: kd> ln fffff801`9737e1c0
(fffff801`9737e1c0)   nt!KiServiceTable 

1: kd> dd fffff801`9737e1c0 L8
fffff801`9737e1c0  fd3c4504 fd43c200 0158d442 0370ca40
fffff801`9737e1d0  0193a400 fe5e2300 019dab05 019e3206

1: kd> u fffff801`9737e1c0 + (019dab05 >> 4)
nt!NtReadFile:
fffff801`9751bc70 4c894c2420      mov     qword ptr [rsp+20h], r9
```

The low-order nibble is used to hold the number of arguments passed thru the stack. The Windows ABI uses RCX, RDX, R8 and R9 for the first 4 arguments. From the above example, we can deduce that NtReadFile takes 9 arguments.

# Demo
![demo1](/assets/custom_syscall.gif)

![demo2](/assets/custom_syscall1.gif)
