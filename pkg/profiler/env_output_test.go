//go:build linux

package profiler

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newTestRunner() *Runner {
	return NewRunner(8080, "", "", "", nil, nil, "", "")
}

// runnerWithEnv returns a runner that already knows the environment of pid 42,
// standing in for /proc/42/environ.
func runnerWithEnv(env map[string]string) *Runner {
	r := newTestRunner()
	r.pidEnv[42] = env
	return r
}

func TestShouldProfilePIDReadsOptIn(t *testing.T) {
	ok, profile, name := runnerWithEnv(map[string]string{
		"ADI_PROFILE": "local", "ADI_PROFILE_NAME": "shop",
	}).shouldProfilePID(42)
	if !ok || profile != "local" || name != "shop" {
		t.Fatalf("got ok=%v profile=%q name=%q", ok, profile, name)
	}

	if ok, _, _ := runnerWithEnv(map[string]string{
		"ADI_PROFILE": "local", "ADI_PROFILE_DISABLED": "1",
	}).shouldProfilePID(42); ok {
		t.Fatal("ADI_PROFILE_DISABLED=1 should opt the process out")
	}
	if ok, _, _ := runnerWithEnv(map[string]string{}).shouldProfilePID(42); ok {
		t.Fatal("a process without ADI_PROFILE must not be profiled")
	}
}

func writeEnvFor(t *testing.T, includeValues bool) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "env.yaml")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	r := runnerWithEnv(map[string]string{
		"RCTEST_DB_PASSWORD": "hunter2-secret",
		"RCTEST_DB_HOST":     "db.internal",
		"OTHER":              "ignored",
	})
	r.SetIncludeEnvValues(includeValues)
	r.envPrefixes = []string{"RCTEST_"}
	r.collectAndWriteEnv(42, file)

	out, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func TestEnvOutputDefaultsToNamesOnly(t *testing.T) {
	out := writeEnvFor(t, false)
	if !strings.Contains(out, "env_names:") || !strings.Contains(out, "- RCTEST_DB_HOST") {
		t.Fatalf("missing names:\n%s", out)
	}
	if strings.Contains(out, "hunter2-secret") || strings.Contains(out, "db.internal") {
		t.Fatalf("values leaked into names-only output:\n%s", out)
	}
}

func TestEnvOutputWithValuesStillRedactsSecrets(t *testing.T) {
	out := writeEnvFor(t, true)
	if !strings.Contains(out, `RCTEST_DB_HOST: "db.internal"`) {
		t.Fatalf("missing value:\n%s", out)
	}
	if strings.Contains(out, "hunter2-secret") || !strings.Contains(out, "[REDACTED]") {
		t.Fatalf("secret not redacted:\n%s", out)
	}
}
