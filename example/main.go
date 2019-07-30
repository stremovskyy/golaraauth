package main

import (
	"github.com/golang/glog"
	"github.com/karmadon/golaraauth"
)

func main() {
	model := struct {
		ID        int64
		TokenID   string
		CreatedAt string
		UpdatedAt string
	}{}

	dbConfig := golaraauth.DbConfig{
		HostName:       "127.0.0.1",
		Port:           "3306",
		Username:       "root",
		Password:       "123698741",
		DbName:         "123456",
		TokensTable:    "cab_tokens",
		TokensTableCol: "token_id",
	}

	config := golaraauth.AuthConfig{
		DbConfig:       dbConfig,
		PrivateKeyFile: "example/keys/dev.rsa",
		PublicKeyFile:  "example/keys/dev.rsa.pub",
	}

	a := golaraauth.LaravelAuthenticator{}
	err := a.New(config)
	if err != nil {
		glog.Fatal(err)
	}

	defer a.CloseDBConnection()

	tokenString := "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImp0aSI6IjNmZWYzZjkzZDg3MGQ4ZTY5ZTEwMWY4ZTk4NTEzNzE5OTJiNGNlZjM0ZjFjY2FjZTZjN2RmZWNmZTgwMjZiMzgyMjQ2ZTA3YjgwNmVhYTk0In0.eyJhdWQiOiIxIiwianRpIjoiM2ZlZjNmOTNkODcwZDhlNjllMTAxZjhlOTg1MTM3MTk5MmI0Y2VmMzRmMWNjYWNlNmM3ZGZlY2ZlODAyNmIzODIyNDZlMDdiODA2ZWFhOTQiLCJpYXQiOjE1NjQ0NzU1ODUsIm5iZiI6MTU2NDQ3NTU4NSwiZXhwIjoxNTk2MDk3OTg1LCJzdWIiOiI0Iiwic2NvcGVzIjpbXX0.sjJImOJ0G83YzkKu0_giOrxxFhOnjGotDepjwyJY8GQVycmB2avecScQ4ExatisF2Uyz4w1REn-vPL_CoYxrKYIdjFVe0-VhobkCsLlYnbnAyJabGSrKIDDpIFByfXeh8uWbbPfT0gVvcG7mk2yVLHb2tCZPpG8VVJI3mGoDJJYtPzmEW0V4ynwhLKUHpcRc-oyLoN8YlfvSjSJYcw5Pjx0orJZueOw-dc6TXbFe-DOVEVJD4yk9ebsYcgxq6IR5YZ7q-wugezYm61IQLcxzAfsQWB3VFt2yi3EJyTxoAj_HKoLQM8wsTYtY6ejVH4k0B_gPC23qROQYpvJznV4zeomBPzPwEvtX1CwE8Vb5KqM28eT5SCKEmFH_wBGBwFAkwrBTvTtc_MkKC53Nehihewo6epoksOKMs-jQcP2bd-vt3l6Qu24EBP5INkSG0PgCKvLMLfqexC-Pprlalz6PXSVNUoiuOlLS_gW1ztqpTbEpwwk1Ux5rxmANRzRiTJTSl7L0I1mcV5xQ-9TcRbqi42YGoRY1U-SxSLzVfTp7GpHnBsrcuPQztlZ9k7o16VbFJ0ZkX2FGf4fCOQ4InJpfs6Oq6fm_wZCAZsQCiYSqYObertaSNRT0tFxjLGbgAYjLybuNBnD7PywYPTlMI4wyzL3355RV9y0zkHjwDihbrUI"
	b, err := a.VerifyTokenString(tokenString, &model)
	if err != nil {
		glog.Error(err)
	}

	println(b)
}
