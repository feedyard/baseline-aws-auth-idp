import os
import json
import urllib.request
import pkg_resources
import boto3
import shutil
import subprocess

from functools import reduce
from copy import copy
from auth0.v3.authentication import GetToken
from auth0.v3.management import Auth0
resource_package = __name__





class Bootstrapt:
    def __init__(self, environ=os.environ):
        self.environ = environ

    def run(self, config):
        auth0builder = Auth0Builder(config["idp"])

        self.auth0_client = create_auth0_client(config)

        def add_org_name(mapping):
            org_name = config['github']['github_organization']
            new_mapping = copy(mapping)
            new_mapping['idp_role'] = f"{org_name}/{mapping['idp_role']}"
            return new_mapping

        account_configs = self.configure_accounts(auth0builder, config)

        client_ids = map(lambda account_config: account_config['client']['client_id'], account_configs)
        print(client_ids)

        auth0builder.deploy_rules(config['project_name'], {
            "client_ids": client_ids,
            "saml_provider_name": config['saml_provider_name'],
            "roles": map(lambda role_mapping: add_org_name(role_mapping), config['roles'])
        })

    def configure_accounts(self, auth0builder, config):
        accounts = config["accounts"]
        idp = config['idp']
        github = config['github']
        account_configs = []
        for account in accounts:
            account_config = auth0builder.configure_sso(account['name'],
                                                        account['aws_account_number'],
                                                        github['github_client_id'],
                                                        github['github_client_secret'],
                                                        config['saml_provider_name']
                                                        )
            account_configs.append(account_config)
            # self.build_policies(
            #     account['terraform_dir'],
            #     account, config["project_name"],
            #     config['saml_provider_name'],
            #     idp['domain']
            # )
        return account_configs

    # def expect_success(self, return_code):
    #     if return_code != 0:
    #         raise Exception("Command failed.")
    #
    # def build_policies(self, terraform_dir, account, project_name, saml_provider_name, saml_aud):
    #
    #     power_user_roles = self.build_role_list(account['role_mapping']['poweruser'])
    #     readonly_roles = self.build_role_list(account['role_mapping']['readonly'])
    #
    #     bucket_name = f"{project_name}-{account['name']}-{saml_aud}"
    #     command = ["terraform", "init", "-backend=true",
    #                f"-backend-config=bucket={bucket_name}",
    #                "-lock=true",
    #                "-force-copy",
    #                f"-backend-config=key=bootstrap/bootstrap.tfstate",
    #                f"-backend-config=region={account['region']}",
    #                f"-backend-config=access_key={account['aws_access_key_id']}",
    #                f"-backend-config=secret_key={account['aws_secret_access_key']}",
    #                ]
    #
    #     process = subprocess.Popen(command,
    #                                cwd=f"{os.path.dirname(os.path.realpath(__file__))}/resources/terraform/{terraform_dir}")
    #     self.expect_success(process.wait())
    #
    #     process = subprocess.Popen(["terraform", "apply",
    #                                 "-var", f"""aws_access_key={account['aws_access_key_id']}""",
    #                                 "-var", f"""aws_secret_key={account['aws_secret_access_key']}""",
    #                                 "-var", f"""env_name={project_name}""",
    #                                 "-var", f"""power_user_roles={power_user_roles}""",
    #                                 "-var", f"""readonly_roles={readonly_roles}""",
    #                                 "-var", f"""aws_saml_provider={saml_provider_name}""",
    #                                 "-var", f"""saml_aud={saml_aud}""",
    #                                 ],
    #                                cwd=f"{os.path.dirname(os.path.realpath(__file__))}/resources/terraform/{terraform_dir}")
    #     self.expect_success(process.wait())
    #
    # def check_for_terraform(self):
    #     if shutil.which('terraform') is None:
    #         raise Exception("Terraform must be on the class path")
    #
    # def build_role_list(self, role_array):
    #     return ", ".join(role_array)

class Auth0Builder:
    def __init__(self, config):
        self.config = config
        self.auth0_client = create_auth0_client(config)
        self.script_generator = RoleRuleScriptGenerator()

    def create_aws_saml_client(self, client_name, account_id):
        matching_clients = list(filter(lambda c: c['name'] == client_name, self.auth0_client.clients.all()))
        create_client_request = json.loads(
            pkg_resources.resource_string(resource_package, 'base-auth0-client-message.json'))
        create_client_request['name'] = client_name
        create_client_request['client_metadata'] = {
            "aws_account_number": account_id
        }

        if len(matching_clients) == 0:
            print(f"Creating new client {client_name} for account {account_id}.")
            return self.auth0_client.clients.create(create_client_request)
        else:
            print(f"Updating existing client {client_name}.")
            del (create_client_request['jwt_configuration']['secret_encoded'])
            return self.auth0_client.clients.update(matching_clients[0]['client_id'], create_client_request)

    def create_aws_saml_provider(self, client_id, name):
        saml_metadata_document = self.__get_saml_metadata_document(self.config['domain'], client_id)
        with open("saml_metadata.xml", "w") as xml_file:
            xml_file.write(saml_metadata_document)
        # client = boto3.client('iam')
        # matching_saml_providers = list(
        #     filter(lambda provider: provider["Arn"].endswith(name), client.list_saml_providers()['SAMLProviderList']))
        # if len(matching_saml_providers) > 0:
        #     print(f"Updating existing SML provider {name} .")
        #     return client.update_saml_provider(
        #         SAMLProviderArn=matching_saml_providers[0]["Arn"],
        #         SAMLMetadataDocument=saml_metadata_document
        #     )
        # else:
        #     print(f"Creating new SML provider {name} .")
        #     return client.create_saml_provider(
        #         SAMLMetadataDocument=saml_metadata_document,
        #         Name=name)

    def configure_sso(self, client_name, account_id, github_client_id, github_client_secret, saml_provider_name):
        new_client = self.create_aws_saml_client(client_name, account_id)
        new_provider = self.create_aws_saml_provider(new_client['client_id'], saml_provider_name)
        new_connection = self.create_github_connection(f"{client_name}-connection", new_client['client_id'],
                                                       github_client_id, github_client_secret)
        return {"client": new_client, "provider": new_provider, "connection": new_connection}

    def create_github_connection(self, connection_name, enabled_client, github_client_id, github_secret):

        create_connection_request = json.loads(
            pkg_resources.resource_string(resource_package, 'base-github-connection-message.json'))
        create_connection_request['name'] = connection_name
        create_connection_request['enabled_clients'] = [enabled_client]
        create_connection_request['options']['client_id'] = github_client_id
        create_connection_request['options']['client_secret'] = github_secret

        connections = list(filter(lambda c: c['name'] == connection_name, self.auth0_client.connections.all()))
        if len(connections) > 0:
            print(f"Updating connection {connection_name}")
            del create_connection_request['strategy']
            del create_connection_request['name']
            return self.auth0_client.connections.update(connections[0]['id'], create_connection_request)
        else:
            print(f"Created connection {connection_name}")
            return self.auth0_client.connections.create(create_connection_request)

    def deploy_rules(self, client_name, config):
        self.deploy_github_connection_rule(client_name)
        self.deploy_rule_hierarchy(client_name, config)

    def deploy_rule_hierarchy(self, role_hierarchy_rule_name, config):
        self.__deploy_or_overwrite_rule({
            "name": role_hierarchy_rule_name + "-hierarchy-rule",
            "script": self.script_generator.generate_hierarchy(config),
            "stage": "login_success"
        })

    def deploy_github_connection_rule(self, client_name):
        self.__deploy_or_overwrite_rule({
            "name": client_name + "-github-rule",
            "script": pkg_resources.resource_string(resource_package, 'github_connection.js').decode("utf-8"),
            "stage": "login_success"
        })

    def __deploy_or_overwrite_rule(self, body):
        rules = list(filter(lambda c: c['name'] == body['name'], self.auth0_client.rules.all()))
        if len(rules) == 0:
            print(f"Creating rule {body['name']}")
            self.auth0_client.rules.create(body)
        else:
            print(f"Updating rule {body['name']}")
            self.auth0_client.rules.update(rules[0]['id'], {
                "name": body['name'],
                "script": body['script']
            })

    def __get_saml_metadata_document(self, auth0_host, client_id):
        response = urllib.request.urlopen(f"https://{auth0_host}/samlp/metadata/{client_id}")
        if response.status != 200:
            print(f"Request to SAMLP endpoint failed with {response.status} - {response.reason}")
            raise Exception("Failed to get SAML metadata document")
        else:
            return response.read().decode("utf-8")




class RoleRuleScriptGenerator:
    def __init__(self):
        pass

    def generate_hierarchy(self, config):
        return f"""
            function (user, context, callback) {{
                var clientId = "{self.__generate_client_Ids(config)}" ;
                if (clientId) {{
                    var roleMapping = {self.__generate_role_map(config)};
                    var role = "";

                    function hasRole(idpRole, user) {{
                        return user.app_metadata.roles.filter(function(userRole){{
                            return userRole == idpRole;
                        }}).length > 0;
                    }}

                    var samlProvider = "arn:aws:iam::"
                        + context.clientMetadata.aws_account_number +
                        ":saml-provider/{config['saml_provider_name']}";

                    for (var i=0; i < roleMapping.length && !role; i++) {{
                        if (hasRole(roleMapping[i].idpRole, user)) {{
                            role = roleMapping[i].awsRole(user);
                        }}
                    }}
                    user.awsRole = role + "," + samlProvider;

                    if (!user.awsRole) {{
                        return callback("No role could be assigned. Please have your admin check mappings between aws role and github team.", user, context);
                    }}

                    user.awsRoleSession = user.nickname;
                    context.samlConfiguration.mappings = {{
                        'https://aws.amazon.com/SAML/Attributes/Role': 'awsRole',
                        'https://aws.amazon.com/SAML/Attributes/RoleSessionName': 'awsRoleSession'
                    }};


                    if (context.protocol == 'delegation') {{
                        context.addonConfiguration = context.addonConfiguration || {{}};
                        context.addonConfiguration.aws = context.addonConfiguration.aws || {{}};
                        context.addonConfiguration.aws.principal = samlProvider;
                        context.addonConfiguration.aws.role = role;
                    }}
                }}

                callback(null, user, context);
            }}
        """

    def __generate_client_Ids(self, config):

        client_id_strings = map(lambda client_id: f"'{client_id}':true", config['client_ids'])
        return f'''{{ {", ".join(client_id_strings)} }}'''

    def __generate_role_mapping(self, role):
        aws_role_function = f"""
            function(user) {{
                return "arn:aws:iam::" +
                    context.clientMetadata.aws_account_number +
                    ":role/{role['aws_role']}";
            }}
        """

        return f"""{{ idpRole:"{role['idp_role']}", awsRole: {aws_role_function} }}"""

    def __generate_role_map(self, config):
        role_map = reduce(lambda acc, item: acc + ",\n" + item,
                          map(lambda role: self.__generate_role_mapping(role),
                              config['roles']))
        if config:
            return f"""[
                    {role_map}
            ]"""
        else:
            return f"[]"

# get auth0 management api usage token and create auth0_python Auth0 client
def create_auth0_client(config):
    domain = config["domain"]
    token = GetToken(domain).client_credentials(config["client_id"],
                                                config["client_secret"], f"https://{domain}/api/v2/")
    return Auth0(domain, token['access_token'])

