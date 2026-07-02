// Copyright 2025 Hanzo AI, Inc.
// Portions Copyright 2022 The Casdoor Authors. All Rights Reserved.
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

package util

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
)

func GetHmacSha1(keyStr, value string) string {
	key := []byte(keyStr)
	mac := hmac.New(sha1.New, key)
	mac.Write([]byte(value))
	res := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	return res
}

func GetHmacSha256(key string, data string) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(data))

	return hex.EncodeToString(mac.Sum(nil))
}

// LoadCACertPool loads a CA certificate pool from either a file path or a PEM-encoded string.
// The cert parameter can be:
// - A file path to a PEM-encoded certificate file
// - A PEM-encoded certificate string (starts with "-----BEGIN")
// Returns nil pool and nil error if the cert is empty.
func LoadCACertPool(cert string) (*x509.CertPool, error) {
	if cert == "" {
		return nil, nil
	}

	var pemData []byte
	var err error

	// Check if cert is a PEM string or a file path
	if strings.HasPrefix(strings.TrimSpace(cert), "-----BEGIN") {
		pemData = []byte(cert)
	} else {
		// Try to load from file
		pemData, err = os.ReadFile(cert)
		if err != nil {
			return nil, fmt.Errorf("failed to read certificate file: %w", err)
		}
	}

	// Parse the PEM data
	pool := x509.NewCertPool()
	for len(pemData) > 0 {
		var block *pem.Block
		block, pemData = pem.Decode(pemData)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %w", err)
		}
		pool.AddCert(cert)
	}

	if len(pool.Subjects()) == 0 {
		return nil, fmt.Errorf("no valid certificates found in PEM data")
	}

	return pool, nil
}
