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
