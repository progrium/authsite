# authsite

Auth0 and GitHub Pages bootstrapper for static site / SPA hybrid with authentication and ability to self-modify. It is used as the basis for `wanix deploy` in [WANIX](https://github.com/tractordev/wanix).

## Install

Clone and `go build` or just `go install github.com/progrium/authsite` in a Go workspace.

## Usage
The tool is an interactive CLI tool with a single optional argument for your domain.

```
$ authsite yourdomain.com
```

It walks you through the process for any manual steps. Let us know if you have ideas for improvements.

## How it works

Given a domain, `authsite` will verify it points to GitHub Pages, configures an Auth0 tenant for use on the domain, and sets up a GitHub repository with GitHub Pages, and deploys an "auth module" providing a simple JavaScript API for authentication with a placeholder demo index page. 

You can then replace the site with your own static files, using the auth JS module for a single page application or other protected JS functionality. Auth0 is configured to use GitHub for login, only allowing your user to authenticate. This can be changed, but it allows you to get a GitHub access token, which you can use to modify the GitHub branch deploying the site, effectively letting the site self-modify. 

## Auth API

The "auth module" deploys files to `/auth` that handles login flows with Auth0 and contains the JavaScript ES module `/auth/api.js` that you can import and use to interact with authentication. It exposes this API as exported functions:

* `login(redirect?: string)` - This will redirect the user to authenticate and use the optional `redirect` param to redirect back to. It defaults to the current page.
* `logout(redirect?: string)` - This will redirect the user to clear authentication and use the optional `redirect` param to redirect back to. It defaults to the current page.
* `isAuthenticated(): boolean` - Whether or not the user has authenticated.
* `currentUser(): Object|null` - If authenticated, it will return an object with user information. If not authenticated, it returns `null`. If this user is the SITE_ADMIN it will contain a GitHub API access token with `repo` and `profile` scope.
* `accessToken(): string|null` - If authenticated, it will return the Auth0 access token JWT. If not authenticated, it returns `null`.

This auth module and API store user profile and access token state using `localStorage` so this API is usable from any page on this domain. Keep that in mind especially if you work with and allow third-party scripts on your site.

## License

MIT