package logging

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadConfigAndSizeBasedRotation(t *testing.T) {
	tmp := t.TempDir()
	confPath := filepath.Join(tmp, "log.conf")
	conf := `
# test log.conf
log_base_dir=` + filepath.Join(tmp, "logs") + `
log_dir_prefix=server_log
log_file_name=ulre-server.log
max_size_bytes=256
max_files=3
level=DEBUG
also_stdout=false
`
	if err := os.WriteFile(confPath, []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(confPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MaxSizeBytes != 256 || cfg.MaxFiles != 3 || cfg.Level != LevelDebug || cfg.AlsoStdout {
		t.Fatalf("unexpected parsed log.conf: %+v", cfg)
	}

	lg, err := NewRotatingLogger(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer lg.Close()

	if !strings.HasPrefix(filepath.Base(lg.RunDir()), "server_log-") {
		t.Fatalf("expected server_log-<datetime> directory, got %s", lg.RunDir())
	}

	// Write enough entries to trigger multiple rotations beyond max_files=3.
	for i := 0; i < 25; i++ {
		lg.Info("http", "request completed", "seq", i, "path", "/api/v1/policies", "status", 200)
	}

	entries, err := os.ReadDir(lg.RunDir())
	if err != nil {
		t.Fatal(err)
	}
	// Should contain active file + at most max_files (3) archives = <= 4 files.
	if len(entries) < 2 || len(entries) > 4 {
		t.Fatalf("expected active log + <=3 rotated archives, got %d files", len(entries))
	}
}
