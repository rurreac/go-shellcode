# go-shellcode

1. Use `xorme` to convert a raw Shellcode to a XOR slice of bytes.
2. Replace the EncBuf variable in [utils/payload.go](utils/payload.go).
3. Ensure your Build matches your Payload architecture.
4. Build using `-ldflags "-s -w"`. 

A few notes on Windows targets (basic protections enabled):
* To avoid detection, memory protection on execution is restricted to read and execute.
* Due to above reason the provided raw Shellcode CAN NOT be encoded otherwise won't work.
* Avoid using a staged Payload, it will get detected during the 2nd stage.
* Build AMD64 binaries and use `x64` Payloads for ARM64 targets to avoid Payload limitations.

A note on Linux targets:
* Some (or all?) non staged `msfvenom` payloads only allow `elf` as the output format, so 
you'll have to relay on staged Payloads which is OK except in some specific circumstances.
