resource "aws_iam_saml_provider" "github_federation" {
  name                   = "${var.saml_provider_name}"
  saml_metadata_document = "${file("../${var.saml_metadata_filename}")}"
}

resource "aws_iam_policy" "saml_trust_policy" {
  name   = "saml_trust_policy"
  path   = "/"
  policy = "${data.aws_iam_policy_document.saml_trust_policy_document.json}"
}

data "aws_iam_policy_document" "saml_trust_policy_document" {
  statement {
    actions = [
      "sts:AssumeRoleWithSAML"
    ]

    principals {
      type        = "Federated"
      identifiers = ["${aws_iam_saml_provider.github_federation.arn}"]
    }

    condition {
      test     = "StringEquals"
      variable = "SAML:aud"
      values = [
        "https://signin.aws.amazon.com/saml",
      ]
    }
  }
}

resource "aws_iam_role" "map_iam_roles_to_idp_roles" {
  count = "${length(var.idp_aws_role_map)}"

  name = "${var.idp_aws_role_map[count.index]["aws_role"]}"
  assume_role_policy = "${data.aws_iam_policy_document.saml_trust_policy_document.json}"
}

resource "aws_iam_policy" "map_iam_policy_to_idp_role_permissions" {
  count = "${length(var.idp_aws_role_map)}"

  name = "${var.idp_aws_role_map[count.index]["aws_role"]}Policy"
  policy = "${file("${path.module}/policies/${var.idp_aws_role_map[count.index]["aws_role"]}.json")}"
}

resource "aws_iam_policy_attachment" "attachment_role_permissions_to_role" {
  count = "${length(var.idp_aws_role_map)}"

  name = "${var.idp_aws_role_map[count.index]["aws_role"]}_policy_attachment"
  roles      = ["${var.idp_aws_role_map[count.index]["aws_role"]}"]
  policy_arn = "${aws_iam_policy.map_iam_policy_to_idp_role_permissions[count.index].arn}"
}