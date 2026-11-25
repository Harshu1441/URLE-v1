package logging

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

func ParseLevel(s string) Level {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "DEBUG":
		return LevelDebug
	case "WARN", "WARNING":
		return LevelWarn
	case "ERROR":
		return LevelError
	default:
		return LevelInfo
	}
}

func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "DEBUG"
	case LevelWarn:
		return "WARN"
	case LevelError:
		return "ERROR"
	default:
		return "INFO"
	}
}

// Config controls directory naming, size-based rotation, and retention.
type Config struct {
	BaseDir      string
	DirPrefix    string
	FileName     string
	MaxSizeBytes int64
	MaxFiles     int
	Level        Level
	AlsoStdout   bool
}

// DefaultConfig returns production defaults: 500 MB rotation, 10 retained files.
func DefaultConfig() Config {
	return Config{
		BaseDir:      "./logs",
		DirPrefix:    "server_log",
		FileName:     "ulre-server.log",
		MaxSizeBytes: 500 * 1024 * 1024, // 500 MiB
		MaxFiles:     10,
		Level:        LevelInfo,
		AlsoStdout:   true,
	}
}

// LoadConfig reads a key=value log.conf file; missing file falls back to DefaultConfig.
func LoadConfig(path string) (Config, error) {
	cfg := DefaultConfig()
	if path == "" {
		return cfg, nil
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return cfg, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		k := strings.TrimSpace(parts[0])
		v := strings.TrimSpace(parts[1])
		switch k {
		case "log_base_dir":
			if v != "" {
				cfg.BaseDir = v
			}
		case "log_dir_prefix":
			if v != "" {
				cfg.DirPrefix = v
			}
		case "log_file_name":
			if v != "" {
				cfg.FileName = v
			}
		case "max_size_mb":
			if mb, perr := strconv.ParseInt(v, 10, 64); perr == nil && mb > 0 {
				cfg.MaxSizeBytes = mb * 1024 * 1024
			}
		case "max_size_bytes":
			if b, perr := strconv.ParseInt(v, 10, 64); perr == nil && b > 0 {
				cfg.MaxSizeBytes = b
			}
		case "max_files":
			if mf, perr := strconv.Atoi(v); perr == nil && mf >= 1 {
				cfg.MaxFiles = mf
			}
		case "level":
			cfg.Level = ParseLevel(v)
		case "also_stdout":
			cfg.AlsoStdout = strings.EqualFold(v, "true") || v == "1" || strings.EqualFold(v, "yes")
		}
	}
	return cfg, sc.Err()
}

// RotatingLogger writes timestamped application logs into <BaseDir>/<DirPrefix>-<datetime>/
// and rotates the active log file whenever it exceeds MaxSizeBytes, keeping up to MaxFiles archives.
type RotatingLogger struct {
	mu      sync.Mutex
	cfg     Config
	runDir  string
	curPath string
	file    *os.File
	curSize int64
	seq     int
}

func NewRotatingLogger(cfg Config) (*RotatingLogger, error) {
	if cfg.BaseDir == "" {
		cfg.BaseDir = "./logs"
	}
	if cfg.DirPrefix == "" {
		cfg.DirPrefix = "server_log"
	}
	if cfg.FileName == "" {
		cfg.FileName = "ulre-server.log"
	}
	if cfg.MaxSizeBytes <= 0 {
		cfg.MaxSizeBytes = 500 * 1024 * 1024
	}
	if cfg.MaxFiles <= 0 {
		cfg.MaxFiles = 10
	}

	stamp := time.Now().Format("2006-01-02_15-04-05")
	runDir := filepath.Join(cfg.BaseDir, fmt.Sprintf("%s-%s", cfg.DirPrefix, stamp))
	if err := os.MkdirAll(runDir, 0o750); err != nil {
		return nil, fmt.Errorf("create log directory %s: %w", runDir, err)
	}

	curPath := filepath.Join(runDir, cfg.FileName)
	f, err := os.OpenFile(curPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return nil, fmt.Errorf("open log file %s: %w", curPath, err)
	}
	var curSize int64
	if st, serr := f.Stat(); serr == nil {
		curSize = st.Size()
	}

	return &RotatingLogger{
		cfg:     cfg,
		runDir:  runDir,
		curPath: curPath,
		file:    f,
		curSize: curSize,
	}, nil
}

func (l *RotatingLogger) RunDir() string { return l.runDir }

func (l *RotatingLogger) Debug(component, msg string, kv ...any) {
	l.Log(LevelDebug, component, msg, kv...)
}
func (l *RotatingLogger) Info(component, msg string, kv ...any) {
	l.Log(LevelInfo, component, msg, kv...)
}
func (l *RotatingLogger) Warn(component, msg string, kv ...any) {
	l.Log(LevelWarn, component, msg, kv...)
}
func (l *RotatingLogger) Error(component, msg string, kv ...any) {
	l.Log(LevelError, component, msg, kv...)
}

func (l *RotatingLogger) Log(lvl Level, component, msg string, kv ...any) {
	if lvl < l.cfg.Level {
		return
	}
	var b strings.Builder
	b.WriteString(time.Now().UTC().Format(time.RFC3339Nano))
	b.WriteString(" [")
	b.WriteString(lvl.String())
	b.WriteString("] ")
	b.WriteString(component)
	b.WriteString(": ")
	b.WriteString(msg)
	for i := 0; i+1 < len(kv); i += 2 {
		b.WriteByte(' ')
		b.WriteString(fmt.Sprint(kv[i]))
		b.WriteByte('=')
		b.WriteString(fmt.Sprintf("%q", fmt.Sprint(kv[i+1])))
	}
	b.WriteByte('\n')
	line := b.String()

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.curSize+int64(len(line)) > l.cfg.MaxSizeBytes && l.curSize > 0 {
		_ = l.rotateLocked()
	}
	if l.file != nil {
		if n, err := l.file.WriteString(line); err == nil {
			l.curSize += int64(n)
		}
	}
	if l.cfg.AlsoStdout {
		fmt.Print(line)
	}
}

func (l *RotatingLogger) rotateLocked() error {
	if l.file != nil {
		_ = l.file.Close()
		l.file = nil
	}
	l.seq++
	ext := filepath.Ext(l.cfg.FileName)
	base := strings.TrimSuffix(l.cfg.FileName, ext)
	rotated := filepath.Join(l.runDir, fmt.Sprintf("%s.%04d%s", base, l.seq, ext))
	_ = os.Rename(l.curPath, rotated)

	f, err := os.OpenFile(l.curPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		return err
	}
	l.file = f
	l.curSize = 0
	l.pruneLocked(base, ext)
	return nil
}

func (l *RotatingLogger) pruneLocked(base, ext string) {
	entries, err := os.ReadDir(l.runDir)
	if err != nil {
		return
	}
	var archives []string
	prefix := base + "."
	for _, e := range entries {
		name := e.Name()
		if name == l.cfg.FileName {
			continue
		}
		if strings.HasPrefix(name, prefix) && strings.HasSuffix(name, ext) {
			archives = append(archives, name)
		}
	}
	if len(archives) <= l.cfg.MaxFiles {
		return
	}
	sort.Strings(archives)
	toDelete := len(archives) - l.cfg.MaxFiles
	for i := 0; i < toDelete; i++ {
		_ = os.Remove(filepath.Join(l.runDir, archives[i]))
	}
}

func (l *RotatingLogger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file != nil {
		err := l.file.Close()
		l.file = nil
		return err
	}
	return nil
}
