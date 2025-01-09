package files

import (
	"fmt"
	"os"
)

// ReadFileToBytes reads a file from disk and returns a []byte.
func ReadFileToBytes(filename string) ([]byte, error) {
	bytes, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("error encountered opening %s: %w", filename, err)
	}
	return bytes, nil
}

// SizeInBytes returns the file's size in bytes
func SizeInBytes(path string) int64 {
	fd, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return fd.Size()
}
