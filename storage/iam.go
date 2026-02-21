package storage

import (
	"github.com/hanzoid/oss"
	iamStorage "github.com/hanzoid/oss/casdoor"
)

func NewIamStorageProvider(providerType string, clientId string, clientSecret string, region string, bucket string, endpoint string, cert string, content string) oss.StorageInterface {
	sp := iamStorage.New(&iamStorage.Config{
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
