package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/ulre/ulre/control-plane/api"
	"github.com/ulre/ulre/control-plane/auth"
	"github.com/ulre/ulre/control-plane/database"
	"github.com/ulre/ulre/control-plane/logging"
)

func main() {
	addr := flag.String("addr", ":8080", "HTTP listen address")
	dataDir := flag.String("data-dir", "./data", "persistent control-plane state directory")
	staticDir := flag.String("static-dir", "../frontend/dist", "built React frontend dist directory")
	logConfigPath := flag.String("log-config", "log.conf", "path to log.conf rotation configuration")
	tlsCert := flag.String("tls-cert", "", "optional TLS certificate path")
	tlsKey := flag.String("tls-key", "", "optional TLS private key path")
	flag.Parse()

	if envAddr := os.Getenv("ULRE_ADDR"); envAddr != "" {
		*addr = envAddr
	}

	logCfg, err := logging.LoadConfig(*logConfigPath)
	if err != nil {
		log.Fatalf("load log config %s: %v", *logConfigPath, err)
	}
	logger, err := logging.NewRotatingLogger(logCfg)
	if err != nil {
		log.Fatalf("init rotating logger: %v", err)
	}
	defer logger.Close()

	store, err := database.NewStore(*dataDir)
	if err != nil {
		logger.Error("store", "failed to initialize store", "error", err)
		log.Fatalf("init store: %v", err)
	}
	authMgr, err := auth.NewManager()
	if err != nil {
		logger.Error("auth", "failed to initialize auth", "error", err)
		log.Fatalf("init auth: %v", err)
	}

	srv := api.NewServer(store, authMgr, *staticDir, logger)
	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           srv,
		ReadHeaderTimeout: 10 * time.Second,
	}

	logger.Info("control-plane", "server starting",
		"addr", *addr,
		"data_dir", *dataDir,
		"static_dir", *staticDir,
		"log_dir", logger.RunDir(),
		"max_size_bytes", logCfg.MaxSizeBytes,
		"max_files", logCfg.MaxFiles,
	)

	if *tlsCert != "" && *tlsKey != "" {
		log.Fatal(httpSrv.ListenAndServeTLS(*tlsCert, *tlsKey))
	}
	log.Fatal(httpSrv.ListenAndServe())
}
