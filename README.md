# baseline-aws-auth-idp

 
## identity provider integration

This example is based on Auth0 as the identity provider and uses Github for authentication and authorization, with aws  
roles mapped to github team membership.  

Auth0 prerequisite is creation of a tenant and a default app (machine to machine) for the client id and secret - just  
the minimum to obtain an [access token for using the Management API](https://auth0.com/docs/api/management/v2/tokens).  

See section below for the access credentials associated with this demo.  



### credential requirements

The example assumes the following environment variables are available. Although any number of methods can be used to  
populate the Environment, the pipeline for example demonstrates:
* AWS programmatic keys maintained/retrieved within the repo using openssl public/private encryption.
* All other needed keys retrieved from AWS Secrets Manager

*aws credentials* for the targeted OU master account  
export AWS_ACCOUNT_NUMBER=999999999999  
export AWS_ACCESS_KEY_ID=AKIA••••••••••••••••  
export AWS_SECRET_ACCESS_KEY=••••••••••••••••••••••••••••••••  
export AWS_REGION=us-east-1  

*auth0 tenant and application client credentials*  
export AUTH0_TENANT=mytenantdomain.auth0.com   
export AUTH0_APP_CLIENT_ID=••••••••••••••••  
export AUTH0_APP_CLIENT_SECRET=••••••••••••••••••••••••••••••  

*github oauth app client credentials and access token*  
export GITHUB_ORGANIZATION=github org that contains the teams used to define access permissions  
export GITHUB_OAUTH_APP_CLIENT_ID=••••••••••••••••  
export GITHUB_OAUTH_APP_CLIENT_SECRET=••••••••••••••••••••••••••••••••  
export GITHUB_AUTOMATION_TOKEN=••••••••••••personal access token for github org automation user (e.g., machine account)  
