package auth

import (
	"crypto/rsa"
	"github.com/jmoiron/sqlx"
	"fmt"
	"encoding/hex"
	"crypto/x509"
	"github.com/hashicorp/golang-lru"
)

type MemoryKeyStore struct {
	keyStore map[string]*rsa.PrivateKey
}

func NewMemoryKeyStore() *MemoryKeyStore {
	return &MemoryKeyStore{
		keyStore: map[string]*rsa.PrivateKey{},
	}
}

func (mks *MemoryKeyStore) Get(appID string) (*rsa.PrivateKey, error) {
	if key, ok := mks.keyStore[appID]; ok {
		return key, nil
	}
	return nil, NewAppIDMissingError(appID)
}

func (mks *MemoryKeyStore) Set(appID string, pk *rsa.PrivateKey) {
	mks.keyStore[appID] = pk
}

type PgKeyStore struct {
	db *sqlx.DB
	tableName string
}

func NewPgKeyStore(db *sqlx.DB, tableName string) *PgKeyStore {
	return &PgKeyStore{
		db: db,
		tableName: tableName,
	}
}

func (pks *PgKeyStore) Get(appID string) (*rsa.PrivateKey, error) {
	type u struct {
		PrivateKey string `db:"private_key"`
	}
	rows := []u{}
	sql := fmt.Sprintf(`
		select
			private_key
		from
			%s
		where
			app_id = $1;
	`, pks.tableName)
	err := pks.db.Select(&rows, sql, appID)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, NewAppIDMissingError(appID)
	}
	row := rows[0]
	return pks.unmarshalPrivateKey(row.PrivateKey)
}

func (pks *PgKeyStore) unmarshalPrivateKey(key string) (*rsa.PrivateKey, error) {
	// unmarshal to private key
	decodedKey, err := hex.DecodeString(key)
	if err != nil {
		return nil, err
	}
	return x509.ParsePKCS1PrivateKey(decodedKey)
}

type ARCCacheKeyStore struct {
	arc *lru.ARCCache
	store IPrivateKeyStore
}

func NewARCCacheKeyStore(store IPrivateKeyStore, size int) (*ARCCacheKeyStore, error) {
	arc, err := lru.NewARC(size)
	if err != nil {
		return nil, err
	}
	return &ARCCacheKeyStore{
		arc: arc,
		store: store,
	}, nil
}

func (acks *ARCCacheKeyStore) Get(appID string) (*rsa.PrivateKey, error) {
	if pk, ok := acks.arc.Get(appID); ok {
		return pk.(*rsa.PrivateKey), nil
	}
	if acks.store != nil {
		pk, err := acks.store.Get(appID)
		if err != nil {
			return nil, err
		}
		acks.arc.Add(appID, pk)
		return pk, nil
	}
	return nil, NewAppIDMissingError(appID)
}
