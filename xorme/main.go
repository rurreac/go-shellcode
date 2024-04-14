package main

import (
	"flag"
	"fmt"
	"github.com/rurreac/go-shellcode/utils"
	"os"
)

func main() {
	filePath := flag.String("file", "", "RAW ShellCode Path")
	xorChar := flag.Int("xor", 51, "byte to encode") // Defaults to Character Q
	flag.Parse()
	if *filePath == "" {
		flag.Usage()
		return
	}

	fBytes, fErr := os.ReadFile(*filePath)
	if fErr != nil {
		panic(fErr)
	}

	prettyPrint(utils.Xor(fBytes, byte(*xorChar)))

}

func prettyPrint(buf []byte) {
	fmt.Printf("var EncBuf = []byte{\n")
	for i, b := range buf {
		fmt.Printf("0x%02x,", b)
		if (i+1)%15 == 0 {
			fmt.Printf("\n")
		}
	}
	fmt.Printf("\n}")
}
