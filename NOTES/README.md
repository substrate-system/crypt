# notes

## Sign Commits

Git commit signing proves who committed the code. npm/github **provenance**
proves how and where the package was built.

Configure Git to use SSH for signing:

```sh
git config --global gpg.format ssh
```

```sh
git config --global user.signingkey ~/.ssh/id_ed25519.pub
```

### Add the key to github

Copy the contents of your `.pub` file and paste it into the **Signing Keys**
section of your account settings.

## Provenance

### OIDC Token

Your CI environment (GitHub/GitLab) creates a temporary identity token.

### Sigstore

`npm` uses this token to request a short-lived certificate from
**Sigstore** (a public good certificate authority).


### Attestation

A "provenance statement" is created, linking the package contents to the
specific Git repository, commit SHA, and workflow file.


### Transparency Log

This signature is recorded in a public, tamper-proof ledger (**Rekor**).

## Audit

When you install the package, you can verify the signatures by running:

```sh
npm audit signatures
```
