terraform {
  required_version = "~> 0.12"
  required_providers {
    aws = "~> 2.14"
  }
  backend "remote" {
    hostname = "app.terraform.io"
    organization = "feedyard"
    workspaces {
      name = "feedyard-master-remote-state"
    }
  }
}

variable "project_name" {}
variable "account_name" {}
variable "saml_provider_name" {}
variable "saml_metadata_filename" {}
variable "github_application_name"{}
variable "idp_aws_role_map" {
  type = "list"
}