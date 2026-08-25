package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallShPreservesExistingEnv(t *testing.T) {
	root := filepath.Join("..", "..")
	script := filepath.Join(root, "deploy", "install.sh")
	raw, err := os.ReadFile(script)
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, need := range []string{"load_existing_env", "backup_existing_env", "H22:"} {
		if !strings.Contains(s, need) {
			t.Fatalf("install.sh missing %q", need)
		}
	}

	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	if err := os.WriteFile(envPath, []byte("SESSION_SECRET=keep-me-secret-value\nALLOWED_STREAM_KEYS=keepkeykeepkeykeepkeykeepkeykeep\nBROADCAST_PASSWORD=studio-pw\n"), 0640); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", "-c", `
set -euo pipefail
env_get() {
	local f="$1" key="$2"
	[[ -f "$f" ]] || return 0
	awk -F= -v k="$key" '
		$0 ~ /^[[:space:]]*#/ { next }
		index($0, "=") == 0 { next }
		$1 == k { sub(/^[^=]*=/, ""); print; exit }
	' "$f"
}
load_existing_env() {
	local f="$1"
	[[ -f "$f" ]] || return 0
	if [[ -z "${SESSION_SECRET:-}" ]]; then SESSION_SECRET="$(env_get "$f" SESSION_SECRET)"; fi
	if [[ -z "${ALLOWED_STREAM_KEYS:-}" ]]; then ALLOWED_STREAM_KEYS="$(env_get "$f" ALLOWED_STREAM_KEYS)"; fi
	if [[ -z "${PASSWORD:-}" ]]; then PASSWORD="$(env_get "$f" BROADCAST_PASSWORD)"; fi
}
SESSION_SECRET=
ALLOWED_STREAM_KEYS=
PASSWORD=
load_existing_env "$0"
printf 'S=%s\n' "$SESSION_SECRET"
printf 'K=%s\n' "$ALLOWED_STREAM_KEYS"
printf 'P=%s\n' "$PASSWORD"
`, envPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	got := string(out)
	if !strings.Contains(got, "S=keep-me-secret-value") {
		t.Fatalf("SESSION_SECRET not loaded: %s", got)
	}
	if !strings.Contains(got, "K=keepkeykeepkeykeepkeykeepkeykeep") {
		t.Fatalf("ALLOWED_STREAM_KEYS not loaded: %s", got)
	}
	if !strings.Contains(got, "P=studio-pw") {
		t.Fatalf("BROADCAST_PASSWORD not loaded: %s", got)
	}
}
