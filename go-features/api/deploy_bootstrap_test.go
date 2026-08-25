package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDocsRejectCurlPipeBash(t *testing.T) {
	roots := []string{
		filepath.Join("..", ".."),
		".",
	}
	var root string
	for _, r := range roots {
		if _, err := os.Stat(filepath.Join(r, "deploy", "bootstrap.sh")); err == nil {
			root = r
			break
		}
	}
	if root == "" {
		t.Fatal("repo root not found")
	}
	bad := "raw.githubusercontent.com/xloveee/livecam/main/deploy/bootstrap.sh"
	files := []string{
		filepath.Join(root, "configure.md"),
		filepath.Join(root, "deploy", "README.md"),
		filepath.Join(root, "deploy", "bootstrap.sh"),
		filepath.Join(root, "deploy", "install.sh"),
	}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		s := string(raw)
		if strings.Contains(s, bad) && strings.Contains(s, "| sudo bash") {
			t.Fatalf("%s still documents curl|bash of main (H21)", f)
		}
		if strings.Contains(s, bad+" |") || strings.Contains(s, bad+"|") {
			t.Fatalf("%s still pipes bootstrap from main (H21)", f)
		}
	}
	boot, err := os.ReadFile(filepath.Join(root, "deploy", "bootstrap.sh"))
	if err != nil {
		t.Fatal(err)
	}
	bs := string(boot)
	if !strings.Contains(bs, "refusing piped bootstrap") {
		t.Fatal("bootstrap must refuse piped live install")
	}
	if !strings.Contains(bs, "INSTALL_REF") {
		t.Fatal("bootstrap must pin INSTALL_REF")
	}
	if !strings.Contains(bs, "GO_SHA256") {
		t.Fatal("bootstrap must require GO_SHA256 when installing Go")
	}
}
