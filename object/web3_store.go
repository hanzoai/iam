// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Persistence for multi-chain wallet login (HIP-0111):
//   - Web3Nonce : single-use, expiring login challenges (anti-replay).
//   - WalletLink: the (chain,address) -> user mapping (one user, N wallets).
//
// Both are registered in object.CreateTables() (ormer Sync2 list).

package object

import (
	"time"

	"github.com/hanzoai/iam/util"
)

// ----------------------------------------------------------------------------
// Web3Nonce -- single-use login nonce.
//
// Minted by GET /v1/iam/web3/nonce, burned by POST /v1/iam/web3/verify. The burn
// is a conditional UPDATE (used=false -> used=true) so two concurrent verifies of
// the same captured proof cannot both win: exactly one UPDATE affects a row.
// ----------------------------------------------------------------------------

type Web3Nonce struct {
	Owner       string `xorm:"varchar(100) notnull pk" json:"owner"`
	Name        string `xorm:"varchar(100) notnull pk" json:"name"` // the nonce string itself
	Chain       string `xorm:"varchar(20)" json:"chain"`
	Address     string `xorm:"varchar(128)" json:"address"`
	Domain      string `xorm:"varchar(128)" json:"domain"`
	CreatedTime string `xorm:"varchar(100)" json:"createdTime"`
	ExpireTime  string `xorm:"varchar(100)" json:"expireTime"`
	Used        bool   `xorm:"bool" json:"used"`
}

func AddWeb3Nonce(n *Web3Nonce) (bool, error) {
	affected, err := ormer.Engine.Insert(n)
	if err != nil {
		return false, err
	}
	return affected != 0, nil
}

// BurnWeb3Nonce atomically consumes a nonce. Returns the row iff it existed, was
// unused, and is unexpired; otherwise (nil, nil). The conditional UPDATE is the
// replay guard -- never split "read then write".
func BurnWeb3Nonce(nonce string) (*Web3Nonce, error) {
	if nonce == "" {
		return nil, nil
	}

	rec := &Web3Nonce{}
	existed, err := ormer.Engine.Where("name = ?", nonce).Get(rec)
	if err != nil {
		return nil, err
	}
	if !existed || rec.Used {
		return nil, nil
	}
	if exp, perr := time.Parse(time.RFC3339, rec.ExpireTime); perr == nil {
		if time.Now().After(exp) {
			return nil, nil
		}
	}

	// Conditional, single-row UPDATE: used=false -> true. affected==0 means
	// another request already burned it (lost the race) -> treat as invalid.
	affected, err := ormer.Engine.
		Where("owner = ? AND name = ? AND used = ?", rec.Owner, rec.Name, false).
		Cols("used").
		Update(&Web3Nonce{Used: true})
	if err != nil {
		return nil, err
	}
	if affected == 0 {
		return nil, nil
	}
	rec.Used = true
	return rec, nil
}

// PurgeExpiredWeb3Nonces is a janitor for a periodic task (optional).
func PurgeExpiredWeb3Nonces() (int64, error) {
	return ormer.Engine.Where("expire_time < ?", time.Now().Format(time.RFC3339)).Delete(&Web3Nonce{})
}

// ----------------------------------------------------------------------------
// WalletLink -- the (chain,address) -> user binding.
//
// One user can own many links (EVM + Solana + BTC + TON + XRP, and several
// addresses per chain). The (chain,address) pair is globally unique, so a given
// wallet can be bound to at most one identity -- this is what stops a wallet from
// hijacking someone else's account.
//
// Why a side table and not user columns: the legacy model stored one address in
// one varchar per provider (user.web3onboard). That cannot represent N wallets on
// M chains. Values, not places: a link is its own value; the user is referenced,
// not mutated.
// ----------------------------------------------------------------------------

type WalletLink struct {
	Owner       string `xorm:"varchar(100) notnull pk" json:"owner"` // organization
	User        string `xorm:"varchar(100) notnull pk" json:"user"`  // user.Name
	Chain       string `xorm:"varchar(20) notnull pk unique(chain_addr)" json:"chain"`
	Address     string `xorm:"varchar(128) notnull pk unique(chain_addr)" json:"address"`
	Scheme      string `xorm:"varchar(40)" json:"scheme"`
	PublicKey   string `xorm:"varchar(256)" json:"publicKey"`
	CreatedTime string `xorm:"varchar(100)" json:"createdTime"`
}

// GetWalletLink resolves a verified (chain,address) to its link row, scoped to the
// application's organization. Returns (nil, nil) when no wallet is on file.
//
// NOTE: address is compared as the verifier canonicalizes it. For EVM the verifier
// returns a lowercased 0x address, so store + look up the verifier's canonical
// form to keep EVM case-insensitive.
func GetWalletLink(organization, chain, address string) (*WalletLink, error) {
	if organization == "" || chain == "" || address == "" {
		return nil, nil
	}
	link := &WalletLink{}
	existed, err := ormer.Engine.
		Where("owner = ? AND chain = ? AND address = ?", organization, chain, address).
		Get(link)
	if err != nil {
		return nil, err
	}
	if !existed {
		return nil, nil
	}
	return link, nil
}

// GetWalletLinkGlobal resolves a verified (chain,address) across every
// organization. The (chain,address) pair is globally unique, so this returns at
// most one row. Used to enforce "a wallet binds to at most one identity" even
// across orgs before a new link is created.
func GetWalletLinkGlobal(chain, address string) (*WalletLink, error) {
	if chain == "" || address == "" {
		return nil, nil
	}
	link := &WalletLink{}
	existed, err := ormer.Engine.
		Where("chain = ? AND address = ?", chain, address).
		Get(link)
	if err != nil {
		return nil, err
	}
	if !existed {
		return nil, nil
	}
	return link, nil
}

func AddWalletLink(link *WalletLink) (bool, error) {
	if link.CreatedTime == "" {
		link.CreatedTime = util.GetCurrentTime()
	}
	affected, err := ormer.Engine.Insert(link)
	if err != nil {
		return false, err
	}
	return affected != 0, nil
}

func DeleteWalletLink(link *WalletLink) (bool, error) {
	affected, err := ormer.Engine.
		Where("owner = ? AND user = ? AND chain = ? AND address = ?",
			link.Owner, link.User, link.Chain, link.Address).
		Delete(&WalletLink{})
	if err != nil {
		return false, err
	}
	return affected != 0, nil
}

// GetWalletLinksByUser lists every wallet a user has linked (for account UI).
func GetWalletLinksByUser(owner, user string) ([]*WalletLink, error) {
	links := []*WalletLink{}
	err := ormer.Engine.Where("owner = ? AND user = ?", owner, user).Find(&links)
	return links, err
}
