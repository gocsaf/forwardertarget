// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2026 Intevation GmbH <https://intevation.de>

package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"

	_ "github.com/mattn/go-sqlite3" // Link SQLite 3 driver.
)

const schema = `
CREATE TABLE documents (
  id                INTEGER PRIMARY KEY AUTOINCREMENT,
  filename          text,
  publisher         text,
  tracking_id       text,
  validation_status text,
  original          BLOB NOT NULL
);`

type database struct {
	db *sql.DB
}

func newDatabase(ctx context.Context, filename string) (*database, error) {
	create := false
	if _, err := os.Stat(filename); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("stating %q failed: %w", filename, err)
		}
		create = true
	}
	url := filename + "?_journal=WAL&_timeout=5000&_fk=true"
	db, err := sql.Open("sqlite3", url)
	if err != nil {
		return nil, fmt.Errorf("cannot open database %q: %w", filename, err)
	}
	if create {
		if _, err := db.ExecContext(ctx, schema); err != nil {
			return nil, fmt.Errorf("creating database failed: %w",
				errors.Join(err, db.Close()))
		}
	}
	return &database{db: db}, nil
}

func (db *database) close() error {
	return db.db.Close()
}

func (db *database) store(
	ctx context.Context,
	filename, publisher, trackingID, validationStatus *string,
	original []byte,
) error {
	const insertSQL = `` +
		`INSERT INTO documents` +
		`(filename, publisher, tracking_id, validation_status, original)` +
		`VALUES(?, ?, ?, ?, ?)`
	if _, err := db.db.ExecContext(
		ctx, insertSQL,
		filename, publisher, trackingID, validationStatus, original,
	); err != nil {
		return fmt.Errorf("inserting document failed: %w", err)
	}
	return nil
}
