// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2026 Intevation GmbH <https://intevation.de>

// Package main implements a simple forwarder target for the the csaf_downloader and ISDuBA.
package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/klauspost/compress/zstd"
)

type controller struct {
	maxUploadSize int64
	db            *database
}

func (c *controller) forwardTarget(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(rw, "expecting POST request", http.StatusNotFound)
		return
	}
	defer req.Body.Close()
	req.Body = http.MaxBytesReader(rw, req.Body, c.maxUploadSize)
	r, err := req.MultipartReader()
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	var (
		document         any
		calculatedSHA256 = sha256.New()
		calculatedSHA512 = sha512.New()
		s256, s512       []byte
		original         bytes.Buffer
		validationStatus *string
		filename         *string
		zenc             *zstd.Encoder
	)

	var sb strings.Builder
	toString := func(r io.Reader) (string, error) {
		sb.Reset()
		if _, err := io.Copy(&sb, r); err != nil {
			return "", err
		}
		return sb.String(), nil
	}

	decodeHash := func(r io.Reader, target *[]byte, name string) bool {
		h, err := toString(r)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusBadRequest)
			return false
		}
		if *target, err = hex.DecodeString(h); err != nil {
			log.Printf("error: Decoding %s from hex failed: %v\n", name, err)
			http.Error(rw, err.Error(), http.StatusBadRequest)
			return false
		}
		return true
	}

	for {
		part, err := r.NextPart()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			http.Error(rw, err.Error(), http.StatusBadRequest)
			return
		}
		switch part.FormName() {
		case "advisory":
			sinks := []io.Writer{calculatedSHA256, calculatedSHA512}
			if c.db != nil {
				if zenc, err = zstd.NewWriter(&original); err != nil {
					log.Printf("error: zstd: %v\n", err)
					http.Error(rw, err.Error(), http.StatusInternalServerError)
					return
				}
				sinks = append(sinks, zenc)
			}
			var (
				writers = io.MultiWriter(sinks...)
				tee     = io.TeeReader(part, writers)
				dec     = json.NewDecoder(tee)
			)
			if err := dec.Decode(&document); err != nil {
				http.Error(rw, err.Error(), http.StatusBadRequest)
				return
			}
			if fn := part.FileName(); fn != "" {
				filename = &fn
			}
		case "hash-256":
			if !decodeHash(part, &s256, "hash-256") {
				return
			}
		case "hash-512":
			if !decodeHash(part, &s512, "hash-512") {
				return
			}
		case "validation_status":
			vs, err := toString(part)
			if err != nil {
				http.Error(rw, err.Error(), http.StatusBadRequest)
				return
			}
			switch vs {
			case "valid", "invalid", "not_validated":
				validationStatus = &vs
			default:
				log.Printf("error: invalid validation_status: %q\n", vs)
				http.Error(rw, "invalid validation_status", http.StatusBadRequest)
				return
			}
		}
	}
	if document == nil {
		http.Error(rw, "advisory not found", http.StatusBadRequest)
		return
	}
	if s256 != nil && !bytes.Equal(calculatedSHA256.Sum(nil), s256) {
		http.Error(rw, "hash-256 does not match", http.StatusBadRequest)
		return
	}
	if s512 != nil && !bytes.Equal(calculatedSHA512.Sum(nil), s512) {
		http.Error(rw, "hash-512 does not match", http.StatusBadRequest)
		return
	}
	if zenc != nil {
		if err := zenc.Close(); err != nil {
			log.Printf("error: zst compressin failed: %v\n", err)
			http.Error(rw, err.Error(), http.StatusBadRequest)
			return
		}
		if err := c.db.store(
			req.Context(),
			filename,
			findString(document, "document/publisher/name"),
			findString(document, "document/tracking/id"),
			validationStatus,
			original.Bytes(),
		); err != nil {
			log.Printf("error: data base error: %v\n", err)
			http.Error(rw, err.Error(), http.StatusBadRequest)
			return
		}
	}
	success := map[string]any{
		"status": "ok",
		"id":     42,
	}
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusOK)
	json.NewEncoder(rw).Encode(success)
}

func findString(doc any, path string) *string {
	if t := findElement(doc, path); t != nil {
		if s, ok := t.(string); ok {
			return &s
		}
	}
	return nil
}

func findElement(doc any, path string) any {
	for n := range strings.SplitSeq(path, "/") {
		m, ok := doc.(map[string]any)
		if !ok {
			return nil
		}
		if doc, ok = m[n]; !ok {
			return nil
		}
	}
	return doc
}

type config struct {
	port          int
	host          string
	maxUploadSize int64
	store         string
}

func run(cfg *config) error {
	c := controller{
		maxUploadSize: cfg.maxUploadSize,
	}
	if cfg.store != "" {
		db, err := newDatabase(cfg.store)
		if err != nil {
			return fmt.Errorf("database error: %w", err)
		}
		defer db.close()
		c.db = db
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/import", c.forwardTarget)
	addr := net.JoinHostPort(cfg.host, strconv.Itoa(cfg.port))
	return http.ListenAndServe(addr, mux)
}

func main() {
	const (
		defaultMaxUploadSize = 512*1024*1024 + 1024
		defaultHost          = "localhost"
		defaultPort          = 8888
		defaultStore         = ""
	)
	var cfg config
	flag.IntVar(&cfg.port, "port", defaultPort, "port of the forward target")
	flag.IntVar(&cfg.port, "p", defaultPort, "port of the forward target (shorthand)")
	flag.StringVar(&cfg.host, "host", defaultHost, "host of the forward target")
	flag.StringVar(&cfg.host, "h", defaultHost, "host of the forward target (shorthand)")
	flag.Int64Var(&cfg.maxUploadSize, "maxupload", defaultMaxUploadSize, "max upload size in bytes")
	flag.Int64Var(&cfg.maxUploadSize, "m", defaultMaxUploadSize, "max upload size (shorthand)")
	flag.StringVar(&cfg.store, "store", defaultStore, "SQLite3 database to store documents in")
	flag.StringVar(&cfg.store, "s", defaultStore, "SQLite3 database to store documents in")
	flag.Parse()
	if err := run(&cfg); err != nil {
		log.Fatalf("error: %v\n", err)
	}
}
