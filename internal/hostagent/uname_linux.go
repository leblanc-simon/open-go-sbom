package hostagent

import "syscall"

// uname renvoie la version du noyau (uname -r) et l'architecture (uname -m).
func uname() (release, machine string) {
	var u syscall.Utsname
	if err := syscall.Uname(&u); err != nil {
		return "", ""
	}
	return charsToString(u.Release[:]), charsToString(u.Machine[:])
}

func charsToString[T int8 | uint8](cs []T) string {
	b := make([]byte, 0, len(cs))
	for _, c := range cs {
		if c == 0 {
			break
		}
		b = append(b, byte(c))
	}
	return string(b)
}
