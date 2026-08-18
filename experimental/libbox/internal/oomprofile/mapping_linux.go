//go:build linux

package oomprofile

import (
	"bytes"
	"os"
	"strconv"
	"strings"
)

func (b *profileBuilder) readMapping() {
	data, _ := os.ReadFile("/proc/self/maps")
	parseProcSelfMaps(data, func(lo, hi, offset uint64, file, buildID string) {
		b.addMappingEntry(lo, hi, offset, file, buildID, false)
	})
	if len(b.mem) == 0 {
		b.addMappingEntry(0, 0, 0, "", "", true)
	}
}

func parseProcSelfMaps(data []byte, addMapping func(lo, hi, offset uint64, file, buildID string)) {
	for len(data) > 0 {
		line, rest, _ := bytes.Cut(data, []byte("\n"))
		data = rest
		fields := bytes.Fields(line)
		if len(fields) < 5 || len(fields[1]) < 3 || fields[1][2] != 'x' {
			continue
		}
		addresses := strings.SplitN(string(fields[0]), "-", 2)
		if len(addresses) != 2 {
			continue
		}
		lo, err := strconv.ParseUint(addresses[0], 16, 64)
		if err != nil {
			continue
		}
		hi, err := strconv.ParseUint(addresses[1], 16, 64)
		if err != nil {
			continue
		}
		offset, err := strconv.ParseUint(string(fields[2]), 16, 64)
		if err != nil {
			continue
		}
		var file string
		if len(fields) > 5 {
			file = string(bytes.Join(fields[5:], []byte(" ")))
			file = strings.TrimSuffix(file, " (deleted)")
		}
		if string(fields[4]) == "0" && file == "" {
			continue
		}
		addMapping(lo, hi, offset, file, "")
	}
}
