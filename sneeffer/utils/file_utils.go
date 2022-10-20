package utils

import (
	"fmt"
	"io/ioutil"
	"os"
)

func SaveDataToFile(data []byte, filePath string) error {
	f, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("error: SaveDataToFile: failed create path %s with error %v", filePath, err)
	}

	_, err = f.Write(data)
	if err != nil {
		return fmt.Errorf("error: SaveDataToFile: failed write sbom to path %s with error %v", filePath, err)
	}

	err = f.Close()
	if err != nil {
		return fmt.Errorf("error: SaveDataToFile: failed close path %s with error %v", filePath, err)
	}

	return nil
}

func FileBytes(filePath string) ([]byte, error) {
	return ioutil.ReadFile(filePath)
}
