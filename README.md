# go-shellcode

1. Use `xorme` to convert a raw Shellcode to a XOR slice of bytes.
2. Replace the EncBuf variable in [utils/payload.go](utils/payload.go).
3. Build using `-ldflags "-s -w"`

A few notes on Windows targets (basic protections enabled):
* To avoid detection, memory protection on execution is restricted to read and execute.
* Due to above reason the provided raw Shellcode CAN NOT be encoded otherwise won't work.
* Avoid using a staged payload, it will get detected during the 2nd stage.