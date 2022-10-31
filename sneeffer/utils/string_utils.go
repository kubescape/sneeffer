package utils

import "strings"

func ReplaceChars(str string, allowedChars string, replaceToChar string) string {
	for i := 0; i < len(str); i++ {
		if !strings.Contains(allowedChars, string(str[i])) {
			str = strings.Replace(str, string(str[i]), replaceToChar, 1)
		}
	}
	return str
}

func Between(value string, a string, b string) string {
	// Get substring between two strings.
	posFirst := strings.Index(value, a)
	if posFirst == -1 {
		return ""
	}
	posLast := strings.Index(value, b)
	if posLast == -1 {
		return ""
	}
	posFirstAdjusted := posFirst + len(a)
	if posFirstAdjusted >= posLast {
		return ""
	}
	return value[posFirstAdjusted:posLast]
}
