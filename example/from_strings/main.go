package main

import (
	"github.com/karmadon/golaraauth"
)

const tokenString = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJhdWQiOiIxIiwianRpIjoiNTQxNTYxMGMwOWRmNzRmMjk4NGZlY2I1MmRiOWQ4NmI1MmRhMThmMGRjNzY1ZDM4OGQ3YzUwYzlkMmUzNGQ5ZTgwNzgzZGRkNjM1YjgxMGIiLCJpYXQiOjE2NTk2MDMxNTUuMDAzODk3LCJuYmYiOjE2NTk2MDMxNTUuMDAzODk5LCJleHAiOjE2OTExMzkxNTQuOTkyODk1LCJzdWIiOiI1Iiwic2NvcGVzIjpbXX0.bveK906BK-vZSRoDWEDuR7vf561ksYqeUK53AwmLuLJrnhuOfPuM82FEMiBcp_0gpatxUyJrJgGqmFTdCCtQmR-CIeX4RNTiHCUr7-AgE-qLC31x4RiTbo54yLxeXJzcO-kI6yA0hM-7mUV9JcmXqLwIXIJOOzQNms31YDU78EzEVc40veh3cxGLoK8YPWStYQk8kp8ic38U1u49d7-kQWm7ET2Qd-JzwHD9zsQnXA4ZZqD1tjvfQ2ew7xFMYYTuK26sXAnlgwzBOKyQCmtnPeWdyQ0PTiNYA6XXJiS1b67YrjR2xPQCv6K9hKQbOYypxhuBemcHLJjnClHFTAhMAWyilUMoi_lls_zlFRvob_1GMNLZlSPhxnGisM0u0Mhryrh199Br297pBoVoGyPntwDvRF64OTBD1zkjSxd6_nuhSaUN9VjjQlbn0IA5zc1t7kMhbLSPNSF19uIVfyVXQTfVV12kTp_3gVYx-xNe99roL3CuYExGzi0rNLxTv3O0XfoU-lSX3jbER2p4FHlpMkitLaptwpc2wfScNCT_Rzer8Sa1t4lO30INASV9veDuHN3dIDEOwP_LpRx0k6Bv0UcUr9ZWv_7kS9gXk8M1x4NZI6mT-TXDq9doijpt1MiN2zTfWkNVzuqiNqQH0euDHEr1ARCO5ULp49uvMgCw0tY"

type DBModel struct {
	ID        int64
	TokenID   string
	CreatedAt string
	UpdatedAt string
}

func main() {
	model := &DBModel{}

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
		DbConfig:   dbConfig,
		PrivateKey: privKey,
		PublicKey:  pubkey,
	}

	a := golaraauth.LaravelAuthenticator{}
	err := a.New(config)
	if err != nil {
		panic(err)
	}

	defer a.CloseDBConnection()

	b, err := a.VerifyTokenString(tokenString, model)
	if err != nil {
		panic(err)
	}

	println(b)
}
