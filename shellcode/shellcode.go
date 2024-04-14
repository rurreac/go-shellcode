//go:build !windows && cgo

package shellcode

/*
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <unistd.h>

void call(char *shellcode, size_t length) {
	if(fork()) {
		return;
	}
	unsigned char *ptr;
	// https://man7.org/linux/man-pages/man2/mmap.2.html
	// Creates a new mapping in the virtual address space of the
	// calling process.  The starting address for the new mapping is
	// specified in addr.
	ptr = (unsigned char *) mmap(0, length, \
		PROT_READ|PROT_WRITE|PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if(ptr == MAP_FAILED) {
		perror("mmap");
		return;
	}
	memcpy(ptr, shellcode, length);
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
	C.call((*C.char)(unsafe.Pointer(&shellcode[0])), (C.size_t)(len(shellcode)))
	return nil
}

func LocalExecute(shellcode []byte) error {
	return Execute(shellcode)
}
