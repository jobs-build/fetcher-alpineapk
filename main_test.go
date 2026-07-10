package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	mrand "math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// buildAPK gzips a tar with the given entries — the shape of a single-member
// apk data segment.
func buildAPK(t *testing.T, entries []tar.Header) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, hdr := range entries {
		h := hdr
		if h.Typeflag == tar.TypeReg {
			h.Size = int64(len("x"))
		}
		if err := tw.WriteHeader(&h); err != nil {
			t.Fatal(err)
		}
		if h.Typeflag == tar.TypeReg {
			if _, err := tw.Write([]byte("x")); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestExtractAPKRewritesAbsoluteSymlinkRootRelative(t *testing.T) {
	// gcc-14.2.0-r6 ships usr/lib/bfd-plugins/liblto_plugin.so ->
	// //usr/libexec/gcc/x86_64-alpine-linux-musl/14.2.0/liblto_plugin.so; an
	// absolute target means "relative to the install root".
	out := t.TempDir()
	apk := buildAPK(t, []tar.Header{
		{Name: ".PKGINFO", Typeflag: tar.TypeReg, Mode: 0o644},
		{Name: "usr/libexec/gcc/liblto_plugin.so", Typeflag: tar.TypeReg, Mode: 0o755},
		{Name: "usr/lib/bfd-plugins/liblto_plugin.so", Typeflag: tar.TypeSymlink, Linkname: "//usr/libexec/gcc/liblto_plugin.so"},
	})
	if err := extractAPK(bytes.NewReader(apk), out); err != nil {
		t.Fatalf("extractAPK: %v", err)
	}
	link := filepath.Join(out, "usr/lib/bfd-plugins/liblto_plugin.so")
	target, err := os.Readlink(link)
	if err != nil {
		t.Fatalf("readlink: %v", err)
	}
	if want := "../../libexec/gcc/liblto_plugin.so"; target != want {
		t.Fatalf("rewritten target = %q, want %q", target, want)
	}
	// The rewritten link must resolve to the extracted file.
	if _, err := os.Stat(link); err != nil {
		t.Fatalf("stat through symlink: %v", err)
	}
	// .PKGINFO is a control member and must not be extracted.
	if _, err := os.Lstat(filepath.Join(out, ".PKGINFO")); !os.IsNotExist(err) {
		t.Fatalf(".PKGINFO extracted, err=%v", err)
	}
}

func TestExtractAPKKeepsRelativeSymlink(t *testing.T) {
	out := t.TempDir()
	apk := buildAPK(t, []tar.Header{
		{Name: "usr/lib/libfoo.so.1", Typeflag: tar.TypeReg, Mode: 0o755},
		{Name: "usr/lib/libfoo.so", Typeflag: tar.TypeSymlink, Linkname: "libfoo.so.1"},
	})
	if err := extractAPK(bytes.NewReader(apk), out); err != nil {
		t.Fatalf("extractAPK: %v", err)
	}
	target, err := os.Readlink(filepath.Join(out, "usr/lib/libfoo.so"))
	if err != nil {
		t.Fatal(err)
	}
	if target != "libfoo.so.1" {
		t.Fatalf("target = %q, want %q", target, "libfoo.so.1")
	}
}

func TestExtractAPKRejectsEscapingSymlink(t *testing.T) {
	out := t.TempDir()
	apk := buildAPK(t, []tar.Header{
		{Name: "usr/evil", Typeflag: tar.TypeSymlink, Linkname: "../../../etc/passwd"},
	})
	if err := extractAPK(bytes.NewReader(apk), out); err == nil {
		t.Fatal("expected unsafe-symlink error, got nil")
	}
}

// TestRunStreamsLargePayload proves the fetcher does not buffer the .apk in
// memory: fetching a ~32MiB incompressible package must allocate far less than
// the payload. TotalAlloc is monotonic, so the bound is GC-independent. Also
// asserts no temp-file residue pollutes the output tree.
func TestRunStreamsLargePayload(t *testing.T) {
	big := make([]byte, 32<<20)
	rnd := mrand.New(mrand.NewSource(1))
	rnd.Read(big)
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "usr/lib/blob", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(big))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(big); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	body := buf.Bytes()
	sum := sha256.Sum256(body)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	}))
	defer srv.Close()
	oldMirror := mirror
	mirror = srv.URL
	defer func() { mirror = oldMirror }()

	outDir := t.TempDir()
	params, _ := json.Marshal(map[string]string{
		"branch": "v3.22", "repo": "main", "arch": "x86_64",
		"name": "blob", "version": "1.0-r0", "sha256": hex.EncodeToString(sum[:]),
	})
	getenv := func(k string) string {
		switch k {
		case "JOBS_OUTPUT_DIR":
			return outDir
		case "JOBS_FETCH_PARAMS":
			return string(params)
		}
		return ""
	}

	var m0, m1 runtime.MemStats
	runtime.ReadMemStats(&m0)
	code := run(getenv, os.Stderr)
	runtime.ReadMemStats(&m1)
	if code != exitOK {
		t.Fatalf("run = %d, want %d", code, exitOK)
	}
	if alloc := m1.TotalAlloc - m0.TotalAlloc; alloc > 16<<20 {
		t.Fatalf("run allocated %d MiB for a %d MiB payload — download is buffered in memory", alloc>>20, len(body)>>20)
	}

	got, err := os.ReadFile(filepath.Join(outDir, "usr", "lib", "blob"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, big) {
		t.Fatal("extracted content differs")
	}
	ents, err := os.ReadDir(outDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 1 || ents[0].Name() != "usr" {
		t.Fatalf("output dir polluted: %v", ents)
	}
}
