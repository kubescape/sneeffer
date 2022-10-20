package validator

import (
	"armo_sneeffer/internal/logger"
	"fmt"
	"syscall"
)

func int8ToStr(arr []int8) string {
	b := make([]byte, 0, len(arr))
	for _, v := range arr {
		if v == 0x00 {
			break
		}
		b = append(b, byte(v))
	}
	return string(b)
}

func checkKernelVersion() error {
	var uname syscall.Utsname
	if err := syscall.Uname(&uname); err != nil {
		return fmt.Errorf("checkKernelVersion: fail to detect the kernel version")
	}
	kernelVersion := int8ToStr(uname.Sysname[:]) + int8ToStr(uname.Release[:]) + int8ToStr(uname.Version[:])
	logger.Print(logger.DEBUG, false, "kernelVersion: %s\n", kernelVersion)
	return nil
}

func checkNodePrerequsits() error {
	err := checkKernelVersion()
	if err != nil {
		return err
	}
	return nil
}

func CheckPrerequsits() error {
	err := checkNodePrerequsits()
	if err != nil {
		return err
	}
	return nil
}
