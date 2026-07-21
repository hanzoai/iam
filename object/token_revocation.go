// Copyright 2025 The Hanzo Authors. All Rights Reserved.
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

package object

import (
	"time"

	"github.com/hanzoai/iam-v1/util"
)

// RevokedToken represents a revoked OAuth2 token (RFC 7009).
// Tokens are stored by their hash for security.
type RevokedToken struct {
	Id          int64  `xorm:"pk autoincr" json:"id"`
	TokenHash   string `xorm:"varchar(100) notnull unique index" json:"tokenHash"`
	TokenType   string `xorm:"varchar(20)" json:"tokenType"` // "access_token" or "refresh_token"
	RevokedAt   string `xorm:"varchar(100)" json:"revokedAt"`
	RevokedBy   string `xorm:"varchar(100)" json:"revokedBy"` // User who revoked the token
	ClientId    string `xorm:"varchar(100)" json:"clientId"`
	ExpiresAt   string `xorm:"varchar(100)" json:"expiresAt"` // Original token expiration for cleanup
	Owner       string `xorm:"varchar(100)" json:"owner"`
	Application string `xorm:"varchar(100)" json:"application"`
}

// RevokeToken revokes an OAuth2 token (access_token or refresh_token).
// This implements RFC 7009 - OAuth 2.0 Token Revocation.
func RevokeToken(tokenValue string, tokenType string, revokedBy string, clientId string, owner string, application string, expiresAt time.Time) error {
	if tokenValue == "" {
		return nil
	}

	tokenHash := getTokenHash(tokenValue)

	// Check if already revoked
	revoked, err := IsTokenRevoked(tokenValue)
	if err != nil {
		return err
	}
	if revoked {
		// Already revoked, return success (RFC 7009 says this is OK)
		return nil
	}

	revokedToken := &RevokedToken{
		TokenHash:   tokenHash,
		TokenType:   tokenType,
		RevokedAt:   util.GetCurrentTime(),
		RevokedBy:   revokedBy,
		ClientId:    clientId,
		ExpiresAt:   expiresAt.Format(time.RFC3339),
		Owner:       owner,
		Application: application,
	}

	_, err = ormer.Engine.Insert(revokedToken)
	return err
}

// RevokeTokenByHash revokes a token by its hash value.
func RevokeTokenByHash(tokenHash string, tokenType string, revokedBy string, clientId string, owner string, application string, expiresAt time.Time) error {
	if tokenHash == "" {
		return nil
	}

	// Check if already revoked
	exists, err := ormer.Engine.Where("token_hash = ?", tokenHash).Exist(&RevokedToken{})
	if err != nil {
		return err
	}
	if exists {
		return nil
	}

	revokedToken := &RevokedToken{
		TokenHash:   tokenHash,
		TokenType:   tokenType,
		RevokedAt:   util.GetCurrentTime(),
		RevokedBy:   revokedBy,
		ClientId:    clientId,
		ExpiresAt:   expiresAt.Format(time.RFC3339),
		Owner:       owner,
		Application: application,
	}

	_, err = ormer.Engine.Insert(revokedToken)
	return err
}

// IsTokenRevoked checks if a token has been revoked.
func IsTokenRevoked(tokenValue string) (bool, error) {
	if tokenValue == "" {
		return false, nil
	}

	tokenHash := getTokenHash(tokenValue)
	return IsTokenRevokedByHash(tokenHash)
}

// IsTokenRevokedByHash checks if a token has been revoked by its hash.
func IsTokenRevokedByHash(tokenHash string) (bool, error) {
	if tokenHash == "" {
		return false, nil
	}

	return ormer.Engine.Where("token_hash = ?", tokenHash).Exist(&RevokedToken{})
}

// CleanupExpiredRevokedTokens removes revoked tokens that have passed their original expiration time.
// This prevents the revocation table from growing indefinitely.
func CleanupExpiredRevokedTokens() (int64, error) {
	// Delete tokens that expired more than 24 hours ago
	// We keep them for a bit after expiration for audit purposes
	cutoffTime := time.Now().Add(-24 * time.Hour).Format(time.RFC3339)

	result, err := ormer.Engine.Where("expires_at < ? AND expires_at != ''", cutoffTime).Delete(&RevokedToken{})
	return result, err
}

// GetRevokedTokens returns all revoked tokens for an application.
func GetRevokedTokens(owner string, application string) ([]*RevokedToken, error) {
	tokens := []*RevokedToken{}
	err := ormer.Engine.Where("owner = ? AND application = ?", owner, application).
		Desc("revoked_at").
		Find(&tokens)
	return tokens, err
}

// GetRevokedTokenCount returns the count of revoked tokens for an application.
func GetRevokedTokenCount(owner string, application string) (int64, error) {
	return ormer.Engine.Where("owner = ? AND application = ?", owner, application).
		Count(&RevokedToken{})
}
