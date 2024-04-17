package main

import (
	"context"
	"embed"
	"errors"
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
	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/huh/spinner"
	"github.com/charmbracelet/lipgloss"
	"github.com/cli/oauth/api"
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

var (
	domain            string
	oauthClientID     string
	oauthClientSecret string
)

func fatal(err error) {
	if err != nil {
		text := lipgloss.NewStyle().Foreground(lipgloss.Color("#ff0000")).SetString(err.Error())
		fmt.Println(text)
		os.Exit(1)
	}
}

func main() {

	ctx := context.Background()
	theme := huh.ThemeBase16()

	//accessibleMode := os.Getenv("ACCESSIBLE") != ""
	//form.WithAccessible(accessibleMode)

	flag.Parse()
	if len(flag.Args()) == 0 {
		// ask for domain
		fatal(huh.NewInput().
			Title("Enter the domain to use for your auth capable GitHub Pages site:").
			Value(&domain).
			Validate(func(s string) error {
				if s == "" {
					return fmt.Errorf("Domain can't be empty")
				}
				return nil
			}).
			WithTheme(theme).
			Run())
	} else {
		domain = flag.Arg(0)
	}

	fmt.Println(theme.Focused.Title.SetString(fmt.Sprintf("Using domain '%s' for site.", domain)))

	var domainErr error
	fatal(spinner.New().
		Title(fmt.Sprintf("Checking DNS for domain '%s' ...", domain)).
		Action(func() {
			ips, err := net.LookupIP(domain)
			if err != nil {
				var dnsErr *net.DNSError
				if errors.As(err, &dnsErr) {
					domainErr = fmt.Errorf("Domain '%s' is not resolving to any IP.", domain)
					return
				} else {
					fatal(err)
				}
			}

			for _, ip := range ips {
				if !contains(pagesIPs, ip.String()) {
					domainErr = fmt.Errorf("Domain '%s' IPs not pointing to GitHub Pages.", domain)
					return
				}
			}
		}).
		Run())

	if domainErr != nil {
		text := lipgloss.NewStyle().Foreground(lipgloss.Color("#ffff00")).SetString(domainErr.Error())
		fmt.Println(text)

		fmt.Println()
		fmt.Println("Make sure to configure A records to the GitHub Pages IPs:")
		for _, ip := range pagesIPs {
			fmt.Println(" -", ip)
		}
		os.Exit(1)
	}
	fmt.Println(theme.Focused.Title.SetString(fmt.Sprintf("\rDomain '%s' is properly pointing to GitHub Pages.", domain)))

	var hasAuth0 bool
	huh.NewConfirm().
		Title("Do you have an Auth0 account?").
		Value(&hasAuth0).
		Run()

	if !hasAuth0 {
		fmt.Println()
		fmt.Println("TODO: get auth0 free click this URL:")
		fmt.Println("https://auth0.com/signup")
		fmt.Println()
		fmt.Println("TODO: how to setup tenant")
		os.Exit(1)
	}

	state, err := auth.GetDeviceCode(ctx, http.DefaultClient, nil)
	if err != nil {
		log.Fatal("failed to get the device code:", err)
	}

	fmt.Printf("Login to your Auth0 account with this URL ... \n\n%s\n\n", state.VerificationURI)

	var tenantAuth auth.Result
	fatal(spinner.New().
		Title("").
		Action(func() {
			tenantAuth, err = auth.WaitUntilUserLogsIn(ctx, http.DefaultClient, state)
			if err != nil {
				log.Fatal("failed to get the device code:", err)
			}
		}).
		Run())

	fmt.Print("\033[A\033[K")
	fmt.Print("\033[A\033[K")
	fmt.Print("\033[A\033[K")
	fmt.Print("\033[A\033[K")

	fmt.Println(theme.Focused.Title.SetString(fmt.Sprintf("\rLogged into Auth0 with tenant '%s'.", tenantAuth.Tenant)))

	var hasGithub bool
	huh.NewConfirm().
		Title("Do you have a GitHub account?").
		Value(&hasGithub).
		Run()

	if !hasGithub {
		fmt.Println()
		fmt.Println("TODO: get github free click this URL:")
		fmt.Println("https://github.com/signup")
		fmt.Println()
		os.Exit(1)
	}

	clientID := "b5faa9cd34a4fa21d844"
	ghCode, err := device.RequestCode(http.DefaultClient, "https://github.com/login/device/code", clientID, []string{"repo"})
	if err != nil {
		log.Fatal("req code:", err)
	}

	fmt.Printf("Login to your GitHub account with this URL and enter code %s ... \n\n%s\n\n", ghCode.UserCode, ghCode.VerificationURI)

	var ghAuth *api.AccessToken
	var gh *github.Client
	var user *github.User
	fatal(spinner.New().
		Title("").
		Action(func() {
			ghAuth, err = device.Wait(ctx, http.DefaultClient, "https://github.com/login/oauth/access_token", device.WaitOptions{
				ClientID:   clientID,
				DeviceCode: ghCode,
			})
			if err != nil {
				log.Fatal("device wait:", err)
			}

			gh = github.NewClient(nil).WithAuthToken(ghAuth.Token)
			user, _, err = gh.Users.Get(ctx, "")
			if err != nil {
				log.Fatal("user get:", err)
			}
		}).
		Run())

	fmt.Print("\033[A\033[K")
	fmt.Print("\033[A\033[K")
	fmt.Print("\033[A\033[K")
	fmt.Print("\033[A\033[K")

	fmt.Println(theme.Focused.Title.SetString(fmt.Sprintf("\rLogged into GitHub as '%s'.", user.GetLogin())))

	var hasOAuth bool
	huh.NewConfirm().
		Title(fmt.Sprintf("Have you created an OAuth App on GitHub for authenticating on %s?", domain)).
		Value(&hasOAuth).
		Run()

	if !hasOAuth {
		fmt.Println()
		fmt.Println("TODO: setup an oauth app:")
		fmt.Println("https://github.com/settings/applications/new")
		fmt.Println()
		fmt.Println("TODO: recommended fields...")
		fmt.Printf(" - Application name: %s\n", domain)
		fmt.Printf(" - Homepage URL: https://%s\n", domain)
		fmt.Printf(" - Authorization callback URL: https://%s/login/callback\n", tenantAuth.Domain)
		fmt.Println()

		huh.NewNote().
			Description("Press any key to continue").
			Run()
	}

	huh.NewInput().
		Title("Enter the OAuth application Client ID:").
		Value(&oauthClientID).
		Run()

	// todo: tell them to make one
	huh.NewInput().
		Title("Enter the OAuth application Client Secret:").
		Password(true).
		Value(&oauthClientSecret).
		Run()

	var confirmAuth0 bool
	fatal(huh.NewConfirm().
		Title(fmt.Sprintf("WARNING: The following will reset and configure the Auth0 tenant '%s'. Are you sure you want to continue?", tenantAuth.Tenant)).
		Affirmative("Yes").
		Negative("No").
		Value(&confirmAuth0).
		Run())

	if !confirmAuth0 {
		os.Exit(0)
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
			"client_id":        oauthClientID,
			"client_secret":    oauthClientSecret,
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

	fmt.Println(theme.Focused.Title.SetString(fmt.Sprintf("\rAuth0 tenant '%s' has been properly configured.", tenantAuth.Tenant)))

	repoName := domain
	username := user.GetLogin()
	branch := "main"
	path := "/"

	fatal(huh.NewInput().
		Title("A GitHub repository will be created for this site using this name:").
		Value(&repoName).
		Run())

	fatal(huh.NewInput().
		Title("GitHub Pages will be configured to use this branch:").
		Value(&branch).
		Run())

	log.Println("checking for repository...")
	_, resp, err := gh.Repositories.Get(ctx, username, repoName)
	if err != nil && resp.StatusCode != 404 {
		log.Fatal("get repo:", err)
	}
	if resp.StatusCode == 404 {
		log.Println("creating repository...")
		_, _, err = gh.Repositories.Create(ctx, "", &github.Repository{
			Name: github.String(repoName),
		})
		if err != nil {
			log.Fatal("create repo:", err)
		}
	}

	log.Println("committing placeholder index and auth module...")
	for _, path := range []string{"auth/api.js", "auth/auth0-9.23.3.min.js", "auth/auth0-spa-2.0.min.js", "auth/index.html", "index.html"} {
		var sha *string
		f, _, _, err := gh.Repositories.GetContents(ctx, username, repoName, path, nil)
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
		_, _, err = gh.Repositories.UpdateFile(ctx, username, repoName, path, &github.RepositoryContentFileOptions{
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
	_, resp, err = gh.Repositories.GetPagesInfo(ctx, username, repoName)
	if err != nil && resp.StatusCode != 404 {
		log.Fatal(err)
	}
	if resp.StatusCode == 404 {
		log.Println("creating pages...")
		_, _, err := gh.Repositories.EnablePages(ctx, username, repoName, &github.Pages{
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
	_, err = gh.Repositories.UpdatePages(ctx, username, repoName, &github.PagesUpdate{
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
		// TODO: use spinner
		log.Println("checking cert status...")
		pages, _, err := gh.Repositories.GetPagesInfo(ctx, username, repoName)
		if err != nil {
			log.Fatal(err)
		}
		if pages.HTTPSCertificate != nil && (*pages.HTTPSCertificate.State) == "approved" {
			approved = true
		}
		<-time.After(2 * time.Second)
	}
	log.Println("setting enforce https...")
	_, err = gh.Repositories.UpdatePages(ctx, username, repoName, &github.PagesUpdate{
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

	fatal(spinner.New().
		Title("Waiting for site to be deployed...").
		Action(func() {
			for {
				// log.Println("checking build status...")
				pages, _, err := gh.Repositories.GetPagesInfo(ctx, username, repoName)
				if err != nil {
					log.Fatal(err)
				}
				if (*pages.Status) == "built" {
					return
				}
				<-time.After(2 * time.Second)
			}
		}).
		Run())

	fmt.Printf("Site deployed: https://%s\n", domain)
	fmt.Println()
	fmt.Printf("GitHub repository: https://github.com/%s/%s\n", username, repoName)
	fmt.Printf("Auth0 dashboard: https://manage.auth0.com/dashboard/us/%s/\n", tenantAuth.Tenant) // TODO: fix region
	fmt.Println()

}
