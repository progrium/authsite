package main

import (
	"context"
	"embed"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/auth0/go-auth0"
	"github.com/auth0/go-auth0/management"
	"github.com/cli/oauth/device"
	"github.com/google/go-github/v58/github"
	"github.com/progrium/authsite/auth"
)

//go:embed site
var siteDir embed.FS

var pagesIPs = []string{
	"185.199.108.153",
	"185.199.109.153",
	"185.199.110.153",
	"185.199.111.153",
}

func contains(slice []string, str string) bool {
	for _, item := range slice {
		if item == str {
			return true
		}
	}
	return false
}

func main() {
	flag.Parse()
	args := flag.Args()
	// todo: check num args

	ctx := context.Background()
	domain := args[0]
	ghOAuthClientID := ""
	ghOAuthClientSecret := ""

	ips, err := net.LookupIP(domain)
	if err != nil {
		log.Fatal("domain is not resolving to any IP")
	}
	for _, ip := range ips {
		if !contains(pagesIPs, ip.String()) {
			log.Fatal("domain has IP not pointing to GitHub Pages")
		}
	}

	state, err := auth.GetDeviceCode(ctx, http.DefaultClient, nil)
	if err != nil {
		log.Fatal("failed to get the device code:", err)
	}

	fmt.Println(state.VerificationURI)

	tenantAuth, err2 := auth.WaitUntilUserLogsIn(ctx, http.DefaultClient, state)
	if err2 != nil {
		log.Fatal("failed to get the device code:", err)
	}

	api, err := management.New(
		tenantAuth.Domain,
		management.WithStaticToken(tenantAuth.AccessToken),
	)
	if err != nil {
		log.Fatalf("failed to initialize the auth0 management API client: %+v", err)
	}

	fmt.Println("deleting existing clients...")
	cl, err := api.Client.List(ctx)
	if err != nil {
		log.Fatal("list clients:", err)
	}
	for _, c := range cl.Clients {
		if c.GetName() == "All Applications" {
			continue
		}
		if err := api.Client.Delete(ctx, c.GetClientID()); err != nil {
			log.Fatal("delete client:", err)
		}
	}

	fmt.Println("creating internal client used by on-login action...")
	internalClient := &management.Client{
		Name:        auth0.String("internal"),
		Description: auth0.String("used by on-login action"),
		AppType:     auth0.String("non_interactive"),
	}
	err = api.Client.Create(ctx, internalClient)
	if err != nil {
		log.Fatal("create internal client:", err)
	}

	fmt.Println("creating main client...")
	authURLs := []string{fmt.Sprintf("https://%s/auth/", domain)}
	origins := []string{fmt.Sprintf("https://%s", domain)}
	domainClient := &management.Client{
		Name:                    auth0.String(domain),
		Description:             auth0.String(domain),
		AppType:                 auth0.String("spa"),
		Callbacks:               &authURLs,
		AllowedLogoutURLs:       &authURLs,
		AllowedOrigins:          &origins,
		WebOrigins:              &origins,
		TokenEndpointAuthMethod: auth0.String("none"),
	}
	err = api.Client.Create(ctx, domainClient)
	if err != nil {
		log.Fatal("create client:", err)
	}

	fmt.Println("clearing connections...")
	conns, err := api.Connection.List(ctx)
	if err != nil {
		log.Fatal("conn list:", err)
	}
	for _, conn := range conns.Connections {
		if err := api.Connection.Delete(ctx, conn.GetID()); err != nil {
			log.Fatal("conn delete:", err)
		}
	}

	fmt.Println("waiting until cleared...")
	for {
		<-time.After(1 * time.Second)
		conns, err = api.Connection.List(ctx)
		if err != nil {
			log.Fatal("conn list:", err)
		}
		if conns.Total == 0 {
			break
		}
	}

	fmt.Println("setting up github connection...")
	enabledClients := []string{domainClient.GetClientID()}
	err = api.Connection.Create(ctx, &management.Connection{
		Strategy:       auth0.String("github"),
		Name:           auth0.String("github"),
		EnabledClients: &enabledClients,
		Options: map[string]any{
			"follow":           false,
			"profile":          true,
			"read_org":         false,
			"admin_org":        false,
			"read_user":        false,
			"write_org":        false,
			"delete_repo":      false,
			"public_repo":      false,
			"repo_status":      false,
			"notifications":    false,
			"read_repo_hook":   false,
			"admin_repo_hook":  false,
			"read_public_key":  false,
			"repo_deployment":  false,
			"write_repo_hook":  false,
			"admin_public_key": false,
			"write_public_key": false,
			"gist":             false,
			"repo":             true,
			"email":            false,
			"scope":            []string{"repo"},
			"client_id":        ghOAuthClientID,
			"client_secret":    ghOAuthClientSecret,
		},
	})
	if err != nil {
		log.Fatal("conn create:", err)
	}

	fmt.Println("clearing post-login bindings...")
	err = api.Action.UpdateBindings(ctx, "post-login", []*management.ActionBinding{})
	if err != nil {
		log.Fatal("update binding:", err)
	}

	fmt.Println("clearing actions...")
	al, err := api.Action.List(ctx)
	if err != nil {
		log.Fatal("list actions:", err)
	}
	for _, a := range al.Actions {
		if auth0.StringValue(a.Name) == "on-login" {
			err = api.Action.Delete(ctx, a.GetID())
			if err != nil {
				log.Fatal("delete action:", err)
			}
		}
	}

	fmt.Println("creating on-login action...")
	tl, err := api.Action.Triggers(ctx)
	if err != nil {
		log.Fatal("list triggers:", err)
	}
	var trigger management.ActionTrigger
	for _, t := range tl.Triggers {
		if t.GetID() == "post-login" && t.GetStatus() == "CURRENT" {
			trigger = *t
			break
		}
	}
	if trigger.ID == nil {
		log.Fatal("unable to find post-login")
	}

	deps := []management.ActionDependency{{
		Name:    auth0.String("auth0"),
		Version: auth0.String("latest"),
	}}
	secrets := []management.ActionSecret{
		{Name: auth0.String("domain"), Value: auth0.String(tenantAuth.Domain)},
		{Name: auth0.String("admin"), Value: auth0.String("progrium")}, // at least parameterize
		{Name: auth0.String("clientId"), Value: auth0.String(internalClient.GetClientID())},
		{Name: auth0.String("clientSecret"), Value: auth0.String(internalClient.GetClientSecret())},
	}
	code, err := os.ReadFile("on-login.js")
	if err != nil {
		log.Fatal("readfile:", err)
	}
	loginAction := &management.Action{
		Name:              auth0.String("on-login"),
		SupportedTriggers: []management.ActionTrigger{trigger},
		Dependencies:      &deps,
		Secrets:           &secrets,
		Code:              auth0.String(string(code)),
		Runtime:           auth0.String("node18"),
	}
	err = api.Action.Create(ctx, loginAction)
	if err != nil {
		log.Fatal("create action:", err)
	}

	fmt.Println("waiting for on-login action to exist...")
	for {
		al, err := api.Action.List(ctx)
		if err != nil {
			log.Fatal("list actions:", err)
		}
		found := false
		for _, a := range al.Actions {
			if a.GetID() == loginAction.GetID() && a.GetStatus() == "built" {
				found = true
				break
			}
		}
		if found {
			break
		}
		<-time.After(1 * time.Second)
	}

	fmt.Println("deploying on-login action...")
	_, err = api.Action.Deploy(ctx, loginAction.GetID())
	if err != nil {
		log.Fatal("deploy action:", err)
	}

	fmt.Println("waiting for deployment...")
	for {
		<-time.After(1 * time.Second)
		vl, err := api.Action.Versions(ctx, loginAction.GetID())
		if err != nil {
			log.Fatal("list versions:", err)
		}
		if vl.Total >= 1 {
			break
		}
	}

	fmt.Println("creating post-login binding...")
	binding := management.ActionBinding{
		DisplayName: auth0.String("on-login"),
		Ref: &management.ActionBindingReference{
			Type:  auth0.String("action_name"),
			Value: auth0.String("on-login"),
		},
	}
	err = api.Action.UpdateBindings(ctx, "post-login", []*management.ActionBinding{&binding})
	if err != nil {
		log.Fatal("update binding:", err)
	}

	fmt.Println("deleting client grants...")
	gl, err := api.ClientGrant.List(ctx)
	if err != nil {
		log.Fatal("list grants:", err)
	}
	for _, g := range gl.ClientGrants {
		err = api.ClientGrant.Delete(ctx, g.GetID())
		if err != nil {
			log.Fatal("delete grant:", err)
		}
	}

	fmt.Println("creating internal client grant...")
	scope := []string{"read:user_idp_tokens", "read:users"}
	err = api.ClientGrant.Create(ctx, &management.ClientGrant{
		Scope:    &scope,
		Audience: auth0.String(fmt.Sprintf("https://%s/api/v2/", tenantAuth.Domain)),
		ClientID: auth0.String(internalClient.GetClientID()),
	})
	if err != nil {
		log.Fatal("create grant:", err)
	}

	fmt.Println("DONE!")

	// github stuff

	clientID := "b5faa9cd34a4fa21d844"
	scopes := []string{"repo"}
	httpClient := http.DefaultClient

	ghCode, err := device.RequestCode(httpClient, "https://github.com/login/device/code", clientID, scopes)
	if err != nil {
		log.Fatal("req code:", err)
	}

	fmt.Printf("Copy code: %s\n", ghCode.UserCode)
	fmt.Printf("then open: %s\n", ghCode.VerificationURI)

	accessToken, err := device.Wait(ctx, httpClient, "https://github.com/login/oauth/access_token", device.WaitOptions{
		ClientID:   clientID,
		DeviceCode: ghCode,
	})
	if err != nil {
		log.Fatal("device wait:", err)
	}

	gh := github.NewClient(nil).WithAuthToken(accessToken.Token)
	user, _, err := gh.Users.Get(ctx, "")
	if err != nil {
		log.Fatal("user get:", err)
	}

	username := user.GetLogin()
	branch := "main" // TODO: parameterize
	path := "/"

	log.Println("checking for repository...")
	_, resp, err := gh.Repositories.Get(ctx, username, domain)
	if err != nil && resp.StatusCode != 404 {
		log.Fatal("get repo:", err)
	}
	if resp.StatusCode == 404 {
		log.Println("creating repository...")
		_, _, err = gh.Repositories.Create(ctx, "", &github.Repository{
			Name: github.String(domain),
		})
		if err != nil {
			log.Fatal("create repo:", err)
		}
	}

	log.Println("committing placeholder index and auth module...")
	for _, path := range []string{"auth/api.js", "auth/auth0-9.23.3.min.js", "auth/auth0-spa-2.0.min.js", "auth/index.html", "index.html"} {
		var sha *string
		f, _, _, err := gh.Repositories.GetContents(ctx, username, domain, path, nil)
		if f != nil {
			sha = f.SHA
		}
		data, err := fs.ReadFile(siteDir, filepath.Join("site", path))
		if err != nil {
			panic(err)
		}
		if path == "index.html" {
			data = []byte(fmt.Sprintf(string(data), domain))
		}
		if path == "auth/index.html" {
			data = []byte(fmt.Sprintf(string(data), tenantAuth.Domain, domainClient.GetClientID()))
		}
		_, _, err = gh.Repositories.UpdateFile(ctx, username, domain, path, &github.RepositoryContentFileOptions{
			Message: github.String("authsite commit"),
			Branch:  github.String(branch),
			Content: data,
			SHA:     sha,
		})
		if err != nil {
			log.Fatal("commit file:", err)
		}
	}

	log.Println("checking pages...")
	_, resp, err = gh.Repositories.GetPagesInfo(ctx, username, domain)
	if err != nil && resp.StatusCode != 404 {
		log.Fatal(err)
	}
	if resp.StatusCode == 404 {
		log.Println("creating pages...")
		_, _, err := gh.Repositories.EnablePages(ctx, username, domain, &github.Pages{
			Source: &github.PagesSource{
				Branch: github.String(branch),
				Path:   github.String(path),
			},
		})
		if err != nil {
			log.Fatal(err)
		}
	}

	log.Println("setting cname...")
	_, err = gh.Repositories.UpdatePages(ctx, username, domain, &github.PagesUpdate{
		CNAME: github.String(domain),
		Source: &github.PagesSource{
			Branch: github.String(branch),
			Path:   github.String(path),
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	approved := false
	for !approved {
		log.Println("checking cert status...")
		pages, _, err := gh.Repositories.GetPagesInfo(ctx, username, domain)
		if err != nil {
			log.Fatal(err)
		}
		if pages.HTTPSCertificate != nil && (*pages.HTTPSCertificate.State) == "approved" {
			approved = true
		}
		<-time.After(2 * time.Second)
	}
	log.Println("setting enforce https...")
	_, err = gh.Repositories.UpdatePages(ctx, username, domain, &github.PagesUpdate{
		HTTPSEnforced: github.Bool(true),
		CNAME:         github.String(domain),
		Source: &github.PagesSource{
			Branch: github.String(branch),
			Path:   github.String(path),
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	built := false
	for !built {
		log.Println("checking build status...")
		pages, _, err := gh.Repositories.GetPagesInfo(ctx, username, domain)
		if err != nil {
			log.Fatal(err)
		}
		if (*pages.Status) == "built" {
			built = true
		}
		<-time.After(2 * time.Second)
	}
}
