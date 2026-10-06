// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osaudit_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
)

func writeN(t *testing.T, r *osaudit.Recorder, n int) {
	t.Helper()
	line := []byte(strings.Repeat("x", 1000) + "\r\n")
	for written := 0; written < n; written += len(line) {
		if _, err := r.Write(line); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRecordingPrefixVerifiable(t *testing.T) {
	l := openLog(t)
	var buf bytes.Buffer
	r := osaudit.NewRecorder(&buf, l, "E-7K2Q")
	writeN(t, r, 200*1024) // three full chunks and a partial
	// no Close: the session was killed
	mustNoErr(t, osaudit.VerifyRecording(buf.Bytes(), l, "E-7K2Q"))
	covered, err := osaudit.VerifyRecordingPrefix(buf.Bytes(), l, "E-7K2Q")
	mustNoErr(t, err)
	if covered != 3*osaudit.ChunkSize {
		t.Fatalf("log covers %d bytes, want three chunks", covered)
	}
	mustNoErr(t, l.Verify())
}

func TestRecordingClosedCoversEverything(t *testing.T) {
	l := openLog(t)
	var buf bytes.Buffer
	r := osaudit.NewRecorder(&buf, l, "E-AAAA")
	mustNoErr(t, r.Input([]byte("id -u\r")))
	writeN(t, r, 70*1024)
	mustNoErr(t, r.Close("exit"))
	covered, err := osaudit.VerifyRecordingPrefix(buf.Bytes(), l, "E-AAAA")
	mustNoErr(t, err)
	if covered != buf.Len() {
		t.Fatalf("covered %d of %d bytes", covered, buf.Len())
	}
}

func TestRecordingTamperDetected(t *testing.T) {
	l := openLog(t)
	var buf bytes.Buffer
	r := osaudit.NewRecorder(&buf, l, "E-BBBB")
	writeN(t, r, 100*1024)
	mustNoErr(t, r.Close("time box"))
	data := bytes.Clone(buf.Bytes())
	data[10] ^= 0x01
	if err := osaudit.VerifyRecording(data, l, "E-BBBB"); err == nil {
		t.Fatal("a changed recording verified")
	}
	if err := osaudit.VerifyRecording(append(bytes.Clone(buf.Bytes()), "more\n"...), l, "E-BBBB"); err == nil {
		t.Fatal("a recording with bytes after its end verified")
	}
	if err := osaudit.VerifyRecording(buf.Bytes()[:osaudit.ChunkSize], l, "E-BBBB"); err == nil {
		t.Fatal("a truncated recording verified")
	}
}

func TestRecordingIsAsciicast(t *testing.T) {
	l := openLog(t)
	var buf bytes.Buffer
	r := osaudit.NewRecorder(&buf, l, "E-CCCC")
	mustNoErr(t, r.Input([]byte("ls\r")))
	_, err := r.Write([]byte("bin\r\n"))
	mustNoErr(t, err)
	sc := bufio.NewScanner(&buf)
	sc.Scan()
	var header map[string]any
	mustNoErr(t, json.Unmarshal(sc.Bytes(), &header))
	if header["version"] != float64(2) {
		t.Fatalf("header %v", header)
	}
	var kinds []string
	for sc.Scan() {
		var ev []any
		mustNoErr(t, json.Unmarshal(sc.Bytes(), &ev))
		kinds = append(kinds, ev[1].(string))
	}
	if strings.Join(kinds, ",") != "i,o" {
		t.Fatalf("event kinds %v, want both directions", kinds)
	}
}
