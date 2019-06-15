from invoke import task
import os
from tasks.common import load_config
from tasks.auth0.utils import setup_auth0

@task
def integration(ctx, config_file):
    """configure an identity provider for the master OU account in AWS"""
    config = load_config(config_file)

    sso_config = {
        "project_name": config['project_name'],
        "saml_provider_name": config['saml_provider_name'],
        "saml_metadata_filename": config['saml_metadata_filename'],
        "github": {
            "github_application_name": config['github_application_name'],
            "github_client_id": os.environ['GITHUB_CLIENT_ID'],
            "github_client_secret": os.environ['GITHUB_CLIENT_SECRET'],
            "github_organization": os.environ['GITHUB_ORGANIZATION'],
            "github_automation_token": os.environ['GITHUB_AUTOMATION_TOKEN']
        },
        "idp": {
            "domain": os.environ['AUTH0_TENANT'],
            "client_id": os.environ['AUTH0_APP_CLIENT_ID'],
            "client_secret": os.environ['AUTH0_APP_CLIENT_SECRET']
        },
        "account": {
            "name": config['account_name'],
            "aws_account_number": os.environ['AWS_ACCOUNT_NUMBER'],
            "aws_region": os.environ['AWS_REGION'],
        },
        "roles": config['idp_aws_role_map']
    }

    setup_auth0(sso_config)