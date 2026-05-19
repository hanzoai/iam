// Copyright 2021 The Hanzo Authors. All Rights Reserved.
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

package iam

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v4"
)

type Claims struct {
	User
	AccessToken string `json:"accessToken"`
	jwt.RegisteredClaims
	TokenType        string `json:"tokenType"`
	RefreshTokenType string `json:"TokenType"`
	SigninMethod     string `json:"signinMethod"`
}

// IsRefreshToken returns true if the token is a refresh token
func (c Claims) IsRefreshToken() bool {
	return c.RefreshTokenType == "refresh-token"
}

// publicKeyFromPEM returns the public key from either an X.509 CERTIFICATE
// PEM block or a PUBLIC KEY / RSA PUBLIC KEY PEM block. IAM serves the
// application's signing key as the X.509 cert PEM (matches what the IAM
// database stores in cert.certificate); some self-hosted configurations
// supply a raw public-key PEM. Accept both so iamsdk consumers don't have
// to know the difference.
func publicKeyFromPEM(pemBytes []byte) (interface{}, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("iamsdk: not valid PEM")
	}
	if block.Type == "CERTIFICATE" {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("iamsdk: parse certificate: %w", err)
		}
		return cert.PublicKey, nil
	}
	return x509.ParsePKIXPublicKey(block.Bytes)
}

func (c *Client) ParseJwtToken(token string) (*Claims, error) {
	t, err := jwt.ParseWithClaims(token, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		switch token.Method.Alg() {
		case jwt.SigningMethodES256.Alg(), jwt.SigningMethodES512.Alg(),
			jwt.SigningMethodRS256.Alg(), jwt.SigningMethodRS512.Alg():
			return publicKeyFromPEM([]byte(c.Certificate))
		default:
			return nil, fmt.Errorf("unsupported signing method: %v", token.Header["alg"])
		}
	})

	if t != nil {
		if claims, ok := t.Claims.(*Claims); ok && t.Valid {
			return claims, nil
		}
	}

	return nil, err
}
