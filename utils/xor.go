package utils

func Xor(buf []byte, char byte) []byte {
	nBuf := make([]byte, 0)
	for _, b := range buf {
		nBuf = append(nBuf, b^char)
	}
	return nBuf
}
