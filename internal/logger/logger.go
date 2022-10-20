package logger

import (
	"log"
)

const (
	ERROR   = 1
	WARNING = 2
	INFO    = 3
	DEBUG   = 4
)

type Logger struct {
	loggerVerbose       uint8
	loggerVerboseString string
	reportURL           string
}

var logger Logger

func convertLoggerVerbose(loggerVerbose string) uint8 {
	switch loggerVerbose {
	case "ERROR":
		return 1
	case "WARNING":
		return 2
	case "INFO":
		return 3
	case "DEBUG":
		return 4
	default:
		log.Printf("loggerVerbose %s is not supported, we will print warning logs and above\n", loggerVerbose)
		return 2
	}
}

func ConfigLogger(loggerVerbose string, reportURL string) {
	loggerVerboseConverted := convertLoggerVerbose(loggerVerbose)
	logger = Logger{
		loggerVerbose:       loggerVerboseConverted,
		loggerVerboseString: loggerVerbose,
		reportURL:           reportURL,
	}
}

func GetLoggerVerbose() uint8 {
	return logger.loggerVerbose
}

func GetLoggerVerboseAsString(loggerVerbose uint8) string {
	switch loggerVerbose {
	case 1:
		return "ERROR"
	case 2:
		return "WARNING"
	case 3:
		return "INFO"
	case 4:
		return "DEBUG"
	default:
		return ""
	}
}

func Print(loggerVerbose uint8, report bool, format string, v ...any) {
	if loggerVerbose <= logger.loggerVerbose {
		if len(v) > 0 {
			log.Printf(GetLoggerVerboseAsString(loggerVerbose)+": "+format, v...)
		} else {
			log.Printf(GetLoggerVerboseAsString(loggerVerbose) + ": " + format)
		}
	}
	if report {
		// report the log
	}
}
