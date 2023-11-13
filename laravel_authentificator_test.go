package golaraauth

import (
	"crypto/rsa"
	"github.com/golang-jwt/jwt/v5"
	"testing"

	"gorm.io/gorm"
)

const expiredTokenString = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImp0aSI6IjNmZWYzZjkzZDg3MGQ4ZTY5ZTEwMWY4ZTk4NTEzNzE5OTJiNGNlZjM0ZjFjY2FjZTZjN2RmZWNmZTgwMjZiMzgyMjQ2ZTA3YjgwNmVhYTk0In0.eyJhdWQiOiIxIiwianRpIjoiM2ZlZjNmOTNkODcwZDhlNjllMTAxZjhlOTg1MTM3MTk5MmI0Y2VmMzRmMWNjYWNlNmM3ZGZlY2ZlODAyNmIzODIyNDZlMDdiODA2ZWFhOTQiLCJpYXQiOjE1NjQ0NzU1ODUsIm5iZiI6MTU2NDQ3NTU4NSwiZXhwIjoxNTk2MDk3OTg1LCJzdWIiOiI0Iiwic2NvcGVzIjpbXX0.sjJImOJ0G83YzkKu0_giOrxxFhOnjGotDepjwyJY8GQVycmB2avecScQ4ExatisF2Uyz4w1REn-vPL_CoYxrKYIdjFVe0-VhobkCsLlYnbnAyJabGSrKIDDpIFByfXeh8uWbbPfT0gVvcG7mk2yVLHb2tCZPpG8VVJI3mGoDJJYtPzmEW0V4ynwhLKUHpcRc-oyLoN8YlfvSjSJYcw5Pjx0orJZueOw-dc6TXbFe-DOVEVJD4yk9ebsYcgxq6IR5YZ7q-wugezYm61IQLcxzAfsQWB3VFt2yi3EJyTxoAj_HKoLQM8wsTYtY6ejVH4k0B_gPC23qROQYpvJznV4zeomBPzPwEvtX1CwE8Vb5KqM28eT5SCKEmFH_wBGBwFAkwrBTvTtc_MkKC53Nehihewo6epoksOKMs-jQcP2bd-vt3l6Qu24EBP5INkSG0PgCKvLMLfqexC-Pprlalz6PXSVNUoiuOlLS_gW1ztqpTbEpwwk1Ux5rxmANRzRiTJTSl7L0I1mcV5xQ-9TcRbqi42YGoRY1U-SxSLzVfTp7GpHnBsrcuPQztlZ9k7o16VbFJ0ZkX2FGf4fCOQ4InJpfs6Oq6fm_wZCAZsQCiYSqYObertaSNRT0tFxjLGbgAYjLybuNBnD7PywYPTlMI4wyzL3355RV9y0zkHjwDihbrUI"
const notValidTokenString = "Not.Valid.Token-String-jQcP2bd-vt3l6Qu24EBP5INkSG0PgCKvLMLfqexC-Pprlalz6PXSVNUoiuOlLS_gW1ztqpTbEpwwk1Ux5rxmANRzRiTJTSl7L0I1mcV5xQ-9TcRbqi42YGoRY1U-SxSLzVfTp7GpHnBsrcuPQztlZ9k7o16VbFJ0ZkX2FGf4fCOQ4InJpfs6Oq6fm_wZCAZsQCiYSqYObertaSNRT0tFxjLGbgAYjLybuNBnD7PywYPTlMI4wyzL3355RV9y0zkHjwDihbrUI"
const wrongTokenString = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImp0aSI6IjNmMjc2ODU5NjVkN2Y5ZDFiYTc3ZmY1MjlhODUyMTA0NGM4NTg3MTI1NWQ1YmQ0ZmFjOGQ2ODk1Y2U3ZDdmMjQ5ZDQzM1jBiYzVlOGQyNGZmIn0.eyJhdWQiOiIxIiwianRpIjoiM2YyNzY4NTk2NWQ3ZjlkMWJhNzdmZjUyOWE4NTIxMDQ0Yzg1ODcxMjU1ZDViZDRmYWM4ZDY4OTVjZTdkN2YyNDlkNDMyMGJjNWU4ZDI0ZmYiLCJpYXQiOjE2MjE5NTc4ODksIm5iZiI6MTYyMTk1Nzg4OSwiZXhwIjoxNjUzNDkzODg5LCJzdWIiOiI1Iiwic2NvcGVzIjpbXX0.Nd7n9OdbKArLuE3fVzF_vRCFTUpLRIyOG9kMh6o37vUtgQlAhzFYmsKF81mBcQzIak0C6mTCXznT7tTdV9jmJiKVYyK26XMIL9eWSz2AkGWlhyS-eC7oorNtz8J4LGoVEhk-ojErc1bWge0o0uM6DhrEuIIatZmVSCl1Hfj9q2p0Vfs-atQQEqCR5ZpcEkS4Nnt34oMyoWtqwZL6hNb-8xO_yLz-XT-i_EQila4ZqwYo77xRPmZbuxtP8ZxXVqP9wHO0G24brK67fPXNXLGasCaPoC3dU2PDgmw9-VoCa68YL9L-hW99G-0mhiPExgH16IyApNNEdtaenCI5qRNPamWD6aF4O3i5w9X_A9kEsyM9_M_vkzX83tFOzDKPYW7_aRD2WEK6I7Nqz509T23YQDbegM4WFuv3u53Kqvnr955rxuPz27ZebySPyKoysBF7wOKMI331JfPATpG1SZm63SMsnel0UzkWVYqJxWrsS_kYeU-qbjD7Fj3KOK7b5UID0r_wOiJTyrW-9l79hwmkOCiMmjhf5X7HGVC3CngTXgB07b0GloKAoJIErQJ8vAEO7QPcFq3wPWdwzpN_wFDfehhdn9LcUUZKzGyt7JkuayBFDyKP_A18_pctusklvrAWwl85CVmtJD99-an6nxEMSktOWRrxsjA2b9NfvNIOuDc"
const validTokenString = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImp0aSI6Ijg4Y2EwYTE4YjhlZmI5YjRkMDg2YWNkMDc2OWE4OTJjMGI0M2FmZWJhYzJkMGIyOTkxMzE2ODE2ZjljZDg2NWJmZWU0ZTU2MWY2NzU4NzlhIn0.eyJhdWQiOiIxIiwianRpIjoiODhjYTBhMThiOGVmYjliNGQwODZhY2QwNzY5YTg5MmMwYjQzYWZlYmFjMmQwYjI5OTEzMTY4MTZmOWNkODY1YmZlZTRlNTYxZjY3NTg3OWEiLCJpYXQiOjE2Mjg3Nzc0NDUsIm5iZiI6MTYyODc3NzQ0NSwiZXhwIjoxNjYwMzEzNDQ1LCJzdWIiOiIzNSIsInNjb3BlcyI6W119.eYOQeDdmH7bdtw8HjBZ78k0-mwZWS_sqsHDdJwnzEO_Nh4HFT-IBcoFh8vwr8WRGwuY2SNcoxsTiJJKaeYtf9BVS9E1koe9vLxemNMOew2XcCI90CPJNLUI7fSDKqpTQ_9TujyGW4wp-ZaUbyRKcGqoi6R0t5PVJHwRgzJ9w2VXBFBnHe8p1bDgyoGmCIYHSA0Zvy2c0LNr3mMmwOuWNKNFpXfBDxg6TudTum0IsVQC15fcRyoUD0fK2hxOhxP9u-XMKc6u8ts5VQKfhLXBUmNXxIDnBCAEldVAYRJSoLl3HKNNo04NlUB1JAB-PTF7DVVUIM7n54_Zer-AWTFVnLSM3TiC_Bfp0u62LDPSZk0M-hpzjbauJEHrAONxi0I-nUt6rfi-rCYBXqQk110inzVN3xmvJ-tBNIgNZGaRlR5lR2wi9k2qJFGgBmflAdQ9a1O8KIR72pgNdDdF_nC6yBtfHa2YeRtxujYK5g-ice4-VFOFbCCj-vsBEBuZ347TfWdGn9oClCI-S2fvCgly4cBvo1f0aMf6xMP8FnHbVaOfJG80Lm0pNDv3YkWKOM19ffG6yU43lVCvE8MRCvRbfY6dZZdZvQkGqwSswNwyvqJadjyBg_fFNaURjHY8OPZlX0QzVirDao9k7UzPUGPZkGwNifRCpAxPRy-W8AaUuX-Y"

func TestLaravelAuthenticator_VerifyTokenString(t *testing.T) {
	type DBModel struct {
		ID        int64
		TokenID   string
		CreatedAt string
		UpdatedAt string
	}
	type fields struct {
		db        *gorm.DB
		signKey   *rsa.PrivateKey
		verifyKey *rsa.PublicKey
		Token     *jwt.Token
		Config    AuthConfig
	}
	type args struct {
		tokenString string
		dbModel     interface{}
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    bool
		wantErr bool
	}{
		{
			name: "Expired Token",
			fields: fields{
				db:        nil,
				signKey:   nil,
				verifyKey: nil,
				Token:     nil,
				Config:    AuthConfig{},
			},
			args: args{
				tokenString: expiredTokenString,
				dbModel:     &DBModel{},
			},
			want:    false,
			wantErr: true,
		}, {
			name: "Not Valid Token",
			fields: fields{
				db:        nil,
				signKey:   nil,
				verifyKey: nil,
				Token:     nil,
				Config:    AuthConfig{},
			},
			args: args{
				tokenString: notValidTokenString,
				dbModel:     &DBModel{},
			},
			want:    false,
			wantErr: true,
		}, {
			name: "Wrong Token",
			fields: fields{
				db:        nil,
				signKey:   nil,
				verifyKey: nil,
				Token:     nil,
				Config:    AuthConfig{},
			},
			args: args{
				tokenString: wrongTokenString,
				dbModel:     &DBModel{},
			},
			want:    false,
			wantErr: true,
		}, {
			name: "Valid Token",
			fields: fields{
				db:        nil,
				signKey:   nil,
				verifyKey: nil,
				Token:     nil,
				Config:    AuthConfig{},
			},
			args: args{
				tokenString: validTokenString,
				dbModel:     &DBModel{},
			},
			want:    true,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dbConfig := DbConfig{
				HostName:       "127.0.0.1",
				Port:           "3306",
				Username:       "root",
				Password:       "123698741",
				DbName:         "123456",
				TokensTable:    "cab_tokens",
				TokensTableCol: "token_id",
			}

			config := AuthConfig{
				DbConfig:       dbConfig,
				PrivateKeyFile: "example/keys/dev.rsa",
				PublicKeyFile:  "example/keys/dev.rsa.pub",
			}

			g := LaravelAuthenticator{}
			err := g.New(config)
			if err != nil {
				panic(err)
			}

			got, err := g.VerifyTokenString(tt.args.tokenString, tt.args.dbModel)
			if (err != nil) != tt.wantErr {
				t.Errorf("VerifyTokenString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("VerifyTokenString() got = %v, want %v", got, tt.want)
			}
		})
	}
}
