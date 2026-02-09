package storage

import (
	"github.com/casdoor/oss"
	casdoorStorage "github.com/casdoor/oss/casdoor"
)

func NewCasdoorStorageProvider(providerType string, clientId string, clientSecret string, region string, bucket string, endpoint string, cert string, content string) oss.StorageInterface {
	sp := casdoorStorage.New(&casdoorStorage.Config{
		clientId,
		clientSecret,
		endpoint,
		cert,
		region,
		content,
		bucket,
	})
	return sp
}
