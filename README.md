# Golaraauth 

golaraauth is a simple authentication provider written in GO used in [Laravel](https://laravel.com/) 5.1+.

with this package you can verify the token string that generated by laravel and return the user model that used in laravel auth provider.


## Installation

```bash
go get github.com/karmadon/golaraauth
```

## Usage

### laravel model
first of all you need to create a model that used in laravel with auth provider

```go
package main

type DBModel struct {
    ID        int64
    TokenID   string
    CreatedAt string
    UpdatedAt string
}
```
this model will be used in the VerifyTokenString method to return the user model


```go
package main

import (
    "fmt"
    "github.com/karmadon/golaraauth"
)


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
		TokensTable:    "user_tokens",
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
```

## License

[MIT](https://choosealicense.com/licenses/mit/)

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## Authors

* **Anton Stremovskyy** - *Initial work* - [Karmadon](https://github.com/karmadon)

## Acknowledgements

 - [Laravel](https://laravel.com/)
 - [jwt-go](https://github.com/golang-jwt/jwt)
 - [gorm](https://gorm.io/gorm)
