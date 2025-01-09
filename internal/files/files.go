package files

import (
	"encoding/xml"
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

// IsValidXML returns true if the file contains valid XML
func IsValidXML(filePath string) (bool, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return false, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	decoder := xml.NewDecoder(file)
	for {
		_, err := decoder.Token()
		if err != nil {
			if err.Error() == "EOF" {
				return true, nil // Successfully reached the end of the file
			}
			return false, fmt.Errorf("invalid XML: %w", err)
		}
	}
}
