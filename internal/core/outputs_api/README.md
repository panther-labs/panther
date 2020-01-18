# outputs-api
CRUD API for alert output encryption and configuration

### Deploying custom Email Verification template
#### Deploying custom Email Verification template for the first time
```
aws ses create-custom-verification-email-template --cli-input-json file://custom_verification_email.json
```

#### Updating custom Email Verification template
```
aws ses update-custom-verification-email-template --cli-input-json file://custom_verification_email.json
```
