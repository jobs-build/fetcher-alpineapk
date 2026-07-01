package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
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
	if err := extractAPK(apk, out); err != nil {
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
	if err := extractAPK(apk, out); err != nil {
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
	if err := extractAPK(apk, out); err == nil {
		t.Fatal("expected unsafe-symlink error, got nil")
	}
}
