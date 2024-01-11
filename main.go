package main

import (
	"context"
	"fmt"
	"net/http"

	"github.com/cli/oauth/device"
	"github.com/google/go-github/v58/github"
	"tractor.dev/toolkit-go/engine"
	"tractor.dev/toolkit-go/engine/cli"
)

func main() {
	engine.Run(Main{})
}

type Main struct {
}

func (m *Main) InitializeCLI(root *cli.Command) {
	root.AddCommand(&cli.Command{
		Usage: "login",
		Run: func(ctx *cli.Context, args []string) {
			// state, err := auth.GetDeviceCode(ctx, http.DefaultClient, nil)
			// if err != nil {
			// 	log.Fatal("failed to get the device code:", err)
			// }
			// fmt.Println(state.UserCode)
			// fmt.Println(state.VerificationURI)
			// result, err2 := auth.WaitUntilUserLogsIn(ctx, http.DefaultClient, state)
			// if err2 != nil {
			// 	log.Fatal("failed to get the device code:", err)
			// }
			// fmt.Println(result.AccessToken)

			clientID := "Iv1.c7987b5ca1fbb091"
			scopes := []string{"administration:write", "pages:write", "repo:write"}
			httpClient := http.DefaultClient

			code, err := device.RequestCode(httpClient, "https://github.com/login/device/code", clientID, scopes)
			if err != nil {
				panic(err)
			}

			fmt.Printf("Copy code: %s\n", code.UserCode)
			fmt.Printf("then open: %s\n", code.VerificationURI)

			accessToken, err := device.Wait(context.TODO(), httpClient, "https://github.com/login/oauth/access_token", device.WaitOptions{
				ClientID:   clientID,
				DeviceCode: code,
			})
			if err != nil {
				panic(err)
			}

			client := github.NewClient(nil).WithAuthToken(accessToken.Token)
			cname := "originalsteak.xyz"
			branch := "master"
			path := "/"
			https := true
			output, _, err := client.Repositories.EnablePages(context.Background(), "progrium", "staticsite", &github.Pages{
				CNAME: &cname,
				Source: &github.PagesSource{
					Branch: &branch,
					Path:   &path,
				},
				HTTPSEnforced: &https,
			})
			if err != nil {
				panic(err)
			}
			fmt.Println(*output)
		},
	})
}
