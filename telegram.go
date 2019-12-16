package telegram

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	cloudkms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/storage"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api"
)

// KeyData contains data neeed to decrypt secured telegram API key:
// KMS key ring and name for decryption, Storage bucket and filename to locate encrypted API key
type KeyData struct {
	Ring     string
	Name     string
	Bucket   string
	Filename string
}

var bot *tgbotapi.BotAPI

// InitTelegram init telegram client
func InitTelegram(ctx context.Context, key KeyData) (*tgbotapi.BotAPI, error) {
	if bot != nil {
		return bot, nil
	}

	buff, err := readEncrypted(ctx, key)
	if err != nil {
		return nil, err
	}

	kmsClient, err := cloudkms.NewKeyManagementClient(ctx)

	projectID := os.Getenv("GCP_PROJECT")
	if projectID == "" {
		return nil, errors.New("Environment variable GCP_PROJECT not set")
	}

	region := os.Getenv("FUNCTION_REGION")
	if region == "" {
		return nil, errors.New("Environment variable FUNCTION_REGION not set")
	}

	decryptRequest := &kmspb.DecryptRequest{
		Name: fmt.Sprintf(
			"projects/%v/locations/%v/keyRings/%v/cryptoKeys/%v",
			projectID, region, key.Ring, key.Name),
		Ciphertext: buff,
	}

	decryptResponse, err := kmsClient.Decrypt(ctx, decryptRequest)
	if err != nil {
		return nil, err
	}

	tgBotKey := strings.TrimSuffix(string(decryptResponse.GetPlaintext()), "\n")

	return tgbotapi.NewBotAPI(tgBotKey)
}

func readEncrypted(ctx context.Context, key KeyData) (buff []byte, err error) {
	client, err := storage.NewClient(ctx)
	if err != nil {
		return
	}
	bth := client.Bucket(key.Bucket)

	obj := bth.Object(key.Filename)

	r, err := obj.NewReader(ctx)
	if err != nil {
		return
	}
	buff = make([]byte, r.Size())
	_, err = r.Read(buff)
	return
}
