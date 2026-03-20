package donations

import (
	"database/sql"
	"log"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type DB struct {
	mu sync.Mutex
	db *sql.DB
}

func OpenDB(path string) (*DB, error) {
	sqlDB, err := sql.Open("sqlite3", path+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, err
	}

	sqlDB.SetMaxOpenConns(1)

	d := &DB{db: sqlDB}
	if err := d.migrate(); err != nil {
		sqlDB.Close()
		return nil, err
	}

	return d, nil
}

func (d *DB) Close() {
	if d != nil && d.db != nil {
		d.db.Close()
	}
}

func (d *DB) migrate() error {
	const schema = `
	CREATE TABLE IF NOT EXISTS streamer_config (
		stream_key  TEXT NOT NULL,
		provider    TEXT NOT NULL,
		config_data TEXT NOT NULL DEFAULT '{}',
		enabled     INTEGER NOT NULL DEFAULT 0,
		updated_at  INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY (stream_key, provider)
	);
	CREATE TABLE IF NOT EXISTS donations (
		id           TEXT PRIMARY KEY,
		stream_key   TEXT NOT NULL,
		viewer_nick  TEXT NOT NULL DEFAULT '',
		amount       INTEGER NOT NULL,
		currency     TEXT NOT NULL DEFAULT 'USD',
		message      TEXT NOT NULL DEFAULT '',
		provider     TEXT NOT NULL,
		status       TEXT NOT NULL DEFAULT 'pending',
		provider_ref TEXT NOT NULL DEFAULT '',
		created_at   INTEGER NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_donations_stream_key ON donations(stream_key);
	CREATE INDEX IF NOT EXISTS idx_donations_status ON donations(status);
	CREATE TABLE IF NOT EXISTS channel_panels (
		stream_key TEXT NOT NULL,
		slot       INTEGER NOT NULL,
		title      TEXT NOT NULL DEFAULT '',
		body       TEXT NOT NULL DEFAULT '',
		image_url  TEXT NOT NULL DEFAULT '',
		link_url   TEXT NOT NULL DEFAULT '',
		enabled    INTEGER NOT NULL DEFAULT 1,
		updated_at INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY (stream_key, slot)
	);
	`
	_, err := d.db.Exec(schema)
	return err
}

func (d *DB) SaveConfig(streamKey, provider, configData string, enabled bool) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	enabledInt := 0
	if enabled {
		enabledInt = 1
	}
	now := time.Now().Unix()

	_, err := d.db.Exec(`
		INSERT INTO streamer_config (stream_key, provider, config_data, enabled, updated_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(stream_key, provider)
		DO UPDATE SET config_data=excluded.config_data, enabled=excluded.enabled, updated_at=excluded.updated_at`,
		streamKey, provider, configData, enabledInt, now)
	return err
}

func (d *DB) GetConfig(streamKey string) ([]ProviderConfig, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	rows, err := d.db.Query(
		`SELECT stream_key, provider, config_data, enabled, updated_at
		 FROM streamer_config WHERE stream_key = ?`, streamKey)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var configs []ProviderConfig
	for rows.Next() {
		var c ProviderConfig
		var enabled int
		if err := rows.Scan(&c.StreamKey, &c.Provider, &c.ConfigData, &enabled, &c.UpdatedAt); err != nil {
			return nil, err
		}
		c.Enabled = enabled != 0
		configs = append(configs, c)
	}
	return configs, rows.Err()
}

func (d *DB) GetEnabledProviders(streamKey string) ([]ProviderConfig, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	rows, err := d.db.Query(
		`SELECT stream_key, provider, config_data, enabled, updated_at
		 FROM streamer_config WHERE stream_key = ? AND enabled = 1`, streamKey)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var configs []ProviderConfig
	for rows.Next() {
		var c ProviderConfig
		var enabled int
		if err := rows.Scan(&c.StreamKey, &c.Provider, &c.ConfigData, &enabled, &c.UpdatedAt); err != nil {
			return nil, err
		}
		c.Enabled = true
		configs = append(configs, c)
	}
	return configs, rows.Err()
}

func (d *DB) InsertDonation(rec *DonationRecord) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec(`
		INSERT INTO donations (id, stream_key, viewer_nick, amount, currency, message, provider, status, provider_ref, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rec.ID, rec.StreamKey, rec.ViewerNick, rec.Amount, rec.Currency,
		rec.Message, rec.Provider, rec.Status, rec.ProviderRef, rec.CreatedAt)
	return err
}

func (d *DB) ConfirmDonation(id, providerRef string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	res, err := d.db.Exec(
		`UPDATE donations SET status = 'confirmed', provider_ref = ? WHERE id = ? AND status = 'pending'`,
		providerRef, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		log.Printf("[donations] confirm: no pending donation found for id=%s", id)
	}
	return nil
}

func (d *DB) FailDonation(id string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec(
		`UPDATE donations SET status = 'failed' WHERE id = ? AND status = 'pending'`, id)
	return err
}

func (d *DB) GetDonation(id string) (*DonationRecord, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	row := d.db.QueryRow(
		`SELECT id, stream_key, viewer_nick, amount, currency, message, provider, status, provider_ref, created_at
		 FROM donations WHERE id = ?`, id)

	var rec DonationRecord
	err := row.Scan(&rec.ID, &rec.StreamKey, &rec.ViewerNick, &rec.Amount,
		&rec.Currency, &rec.Message, &rec.Provider, &rec.Status,
		&rec.ProviderRef, &rec.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &rec, nil
}

func (d *DB) GetHistory(streamKey string, limit int) ([]DonationRecord, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if limit <= 0 || limit > 200 {
		limit = 50
	}

	rows, err := d.db.Query(
		`SELECT id, stream_key, viewer_nick, amount, currency, message, provider, status, provider_ref, created_at
		 FROM donations WHERE stream_key = ? ORDER BY created_at DESC LIMIT ?`,
		streamKey, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []DonationRecord
	for rows.Next() {
		var rec DonationRecord
		if err := rows.Scan(&rec.ID, &rec.StreamKey, &rec.ViewerNick, &rec.Amount,
			&rec.Currency, &rec.Message, &rec.Provider, &rec.Status,
			&rec.ProviderRef, &rec.CreatedAt); err != nil {
			return nil, err
		}
		records = append(records, rec)
	}
	return records, rows.Err()
}

/* ── Channel Panels ──────────────────────────────────────── */

func (d *DB) SavePanel(streamKey string, panel *ChannelPanel) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	enabledInt := 0
	if panel.Enabled {
		enabledInt = 1
	}
	now := time.Now().Unix()

	_, err := d.db.Exec(`
		INSERT INTO channel_panels (stream_key, slot, title, body, image_url, link_url, enabled, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(stream_key, slot)
		DO UPDATE SET title=excluded.title, body=excluded.body, image_url=excluded.image_url,
		              link_url=excluded.link_url, enabled=excluded.enabled, updated_at=excluded.updated_at`,
		streamKey, panel.Slot, panel.Title, panel.Body, panel.ImageURL, panel.LinkURL, enabledInt, now)
	return err
}

func (d *DB) GetPanels(streamKey string) ([]ChannelPanel, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	rows, err := d.db.Query(
		`SELECT slot, title, body, image_url, link_url, enabled
		 FROM channel_panels WHERE stream_key = ? ORDER BY slot ASC`, streamKey)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var panels []ChannelPanel
	for rows.Next() {
		var p ChannelPanel
		var enabled int
		if err := rows.Scan(&p.Slot, &p.Title, &p.Body, &p.ImageURL, &p.LinkURL, &enabled); err != nil {
			return nil, err
		}
		p.Enabled = enabled != 0
		panels = append(panels, p)
	}
	return panels, rows.Err()
}

func (d *DB) GetEnabledPanels(streamKey string) ([]ChannelPanel, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	rows, err := d.db.Query(
		`SELECT slot, title, body, image_url, link_url, enabled
		 FROM channel_panels WHERE stream_key = ? AND enabled = 1 ORDER BY slot ASC`, streamKey)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var panels []ChannelPanel
	for rows.Next() {
		var p ChannelPanel
		if err := rows.Scan(&p.Slot, &p.Title, &p.Body, &p.ImageURL, &p.LinkURL, new(int)); err != nil {
			return nil, err
		}
		p.Enabled = true
		panels = append(panels, p)
	}
	return panels, rows.Err()
}

func (d *DB) DeletePanel(streamKey string, slot int) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec(`DELETE FROM channel_panels WHERE stream_key = ? AND slot = ?`, streamKey, slot)
	return err
}
