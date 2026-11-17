# Publish this project to GitHub

## Before making it public

1. Confirm you have permission to publish the code. If any part was written as part of your employment or on employer systems, confirm the organization permits public release.
2. Rotate the SMTP App Password and Google Chat webhook that appeared in the original pasted source. Generate a fresh ZAP API key too. Do not reuse any exposed values.
3. Review the complete repository for company names, internal hostnames, email addresses, API tokens, screenshots, reports and customer data.
4. Keep the repository private until the review is complete. Change it to Public only after approval.

## Create the GitHub repository

1. Sign in to GitHub as the account that owns the destination repository.
2. Open <https://github.com/new>.
3. Set repository name to `OWASP-ZAP-VAPT-Automation`.
4. Choose **Public** only after the checks above are complete.
5. Do not initialize it with a README, `.gitignore` or license; this project already contains its README and `.gitignore`.
6. Create the empty repository.

## Push from your terminal

Run these commands from the project directory:

```bash
cd OWASP-ZAP-VAPT-Automation

# Confirm the local configuration file is not present.
test ! -f .env

# Initialize Git.
git init -b main

# Stage files.
git add .

# Review every staged filename and change before committing.
git status --short
git diff --cached --stat
git diff --cached

# Commit and connect the empty GitHub repository.
git commit -m "Initial commit: OWASP ZAP VAPT automation"
git remote add origin https://github.com/Aditya-Dalvi/OWASP-ZAP-VAPT-Automation.git
git push -u origin main
```

If the repository is owned by another account, replace the remote URL with that repository's URL.

## After pushing

- Open the repository in a browser and confirm the README renders correctly.
- Confirm `.env`, reports, `.venv`, `__pycache__` and credentials are absent.
- Review GitHub's security alerts and secret-scanning results.
- Do not add a license until you have confirmed you have the right to license all included code.
