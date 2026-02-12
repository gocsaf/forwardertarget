// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2026 Intevation GmbH <https://intevation.de>

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
	"mime/multipart"
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
		http.Error(rw, "expecting POST request", http.StatusBadRequest)
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
	for {
		var part *multipart.Part
		part, err := r.NextPart()
		if err != nil {
			break
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
			var sb strings.Builder
			if _, err := io.Copy(&sb, part); err != nil {
				http.Error(rw, err.Error(), http.StatusBadRequest)
				return
			}
			if s256, err = hex.DecodeString(sb.String()); err != nil {
				http.Error(rw, err.Error(), http.StatusBadRequest)
			}
		case "hash-512":
			var sb strings.Builder
			if _, err := io.Copy(&sb, part); err != nil {
				http.Error(rw, err.Error(), http.StatusBadRequest)
				return
			}
			if s512, err = hex.DecodeString(sb.String()); err != nil {
				http.Error(rw, err.Error(), http.StatusBadRequest)
			}
		case "validation_status":
			var sb strings.Builder
			if _, err := io.Copy(&sb, part); err != nil {
				http.Error(rw, err.Error(), http.StatusBadRequest)
				return
			}
			switch sb.String() {
			case "valid", "invalid", "not_validated":
			default:
				http.Error(rw, "invalid validation_status", http.StatusBadRequest)
				return
			}
		}
	}
	if err != nil && !errors.Is(err, io.EOF) {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
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
	const defaultMaxUploadSize = 512*1024*1024 + 1024
	var (
		port          int
		host          string
		maxUploadSize int64
	)
	flag.IntVar(&port, "port", 8888, "port of the forward target")
	flag.IntVar(&port, "p", 8888, "port of the forward target (shorthand)")
	flag.StringVar(&host, "host", "localhost", "host of the forward target")
	flag.StringVar(&host, "h", "localhost", "host of the forward target (shorthand)")
	flag.Int64Var(&maxUploadSize, "maxupload", defaultMaxUploadSize, "max upload size")
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
