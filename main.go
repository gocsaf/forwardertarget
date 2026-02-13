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
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
)

type controller struct {
	maxUploadSize int64
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
			var (
				writers = io.MultiWriter(calculatedSHA256, calculatedSHA512)
				tee     = io.TeeReader(part, writers)
				dec     = json.NewDecoder(tee)
			)
			if err := dec.Decode(&document); err != nil {
				http.Error(rw, err.Error(), http.StatusBadRequest)
				return
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
	success := map[string]any{
		"status": "ok",
		"id":     42,
	}
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusOK)
	json.NewEncoder(rw).Encode(success)
}

func main() {
	const (
		defaultMaxUploadSize = 512*1024*1024 + 1024
		defaultHost          = "localhost"
		defaultPort          = 8888
	)
	var (
		port          int
		host          string
		maxUploadSize int64
	)
	flag.IntVar(&port, "port", defaultPort, "port of the forward target")
	flag.IntVar(&port, "p", defaultPort, "port of the forward target (shorthand)")
	flag.StringVar(&host, "host", defaultHost, "host of the forward target")
	flag.StringVar(&host, "h", defaultHost, "host of the forward target (shorthand)")
	flag.Int64Var(&maxUploadSize, "maxupload", defaultMaxUploadSize, "max upload size in bytes")
	flag.Int64Var(&maxUploadSize, "m", defaultMaxUploadSize, "max upload size (shorthand)")
	flag.Parse()
	c := controller{
		maxUploadSize: maxUploadSize,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/import", c.forwardTarget)
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	log.Fatal(http.ListenAndServe(addr, mux))
}
