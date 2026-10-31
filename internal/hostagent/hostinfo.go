package hostagent

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// HostInfo est le contexte de l'hôte joint à chaque compte rendu de scan.
type HostInfo struct {
	Hostname     string
	OSID         string
	OSVersion    string
	OSName       string
	Kernel       string
	Arch         string
	ScanDuration time.Duration
}

// osRelease lit /etc/os-release (ou /usr/lib/os-release) sous root.
func osRelease(root string) (id, version, name string) {
	for _, p := range []string{"etc/os-release", "usr/lib/os-release"} {
		f, err := os.Open(filepath.Join(root, p))
		if err != nil {
			continue
		}
		vals := parseOSRelease(f)
		_ = f.Close()
		return vals["ID"], vals["VERSION_ID"], vals["PRETTY_NAME"]
	}
	return "", "", ""
}

// parseOSRelease lit le format clé=valeur d'os-release(5), valeurs entre guillemets ou non.
func parseOSRelease(r io.Reader) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(io.LimitReader(r, 64<<10))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if u, err := strconv.Unquote(v); err == nil {
			v = u
		} else {
			v = strings.Trim(v, `'"`)
		}
		out[strings.TrimSpace(k)] = v
	}
	return out
}

// hostInfo décrit l'hôte : système sous root, noyau et architecture de la machine.
func hostInfo(root, hostname string) HostInfo {
	h := HostInfo{Hostname: hostname, Arch: runtime.GOARCH}
	h.OSID, h.OSVersion, h.OSName = osRelease(root)
	if k, m := uname(); k != "" {
		h.Kernel, h.Arch = k, m
	}
	return h
}

// clip borne une valeur annoncée au serveur, qui refuse les champs trop longs.
func clip(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8Start(s[n]) {
		n--
	}
	return s[:n]
}

func utf8Start(b byte) bool { return b&0xC0 != 0x80 }
