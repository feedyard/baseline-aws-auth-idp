from invoke import task

import boto3
from botocore.exceptions import ClientError

DEFAULT_MASTER_ACCT_TF_STATE_KMS_KEY_ALIAS='alias/master-account-tf-state'
DEFAULT_MASTER_ACCT_TF_STATE_BUCKET='feedyard-master-tf-state'
DEFAULT_MASTER_ACCT_TF_STATE_TAG='managed_by'
DEFAULT_MASTER_ACCT_TF_STATE_TAG_VALUE='feedyard/bootstrap-aws'

@task
def statebucket(ctx, my_profile):
    """create master account terraform state bucket"""
    session = boto3.Session(profile_name=my_profile)

    # create kms key to use for master-account tf state bucket
    kms = session.client('kms')
    try:
        key = kms.describe_key(KeyId=DEFAULT_MASTER_ACCT_TF_STATE_KMS_KEY_ALIAS)
        print('confirm tf state encryption key exists:{}:'.format(DEFAULT_MASTER_ACCT_TF_STATE_KMS_KEY_ALIAS))
        print("> Arn:{}".format(key['KeyMetadata']['Arn']))
    except ClientError as e:
        if e.response['Error']['Code'] == 'NotFoundException':
            try:
                key = kms.create_key(
                    Description='Server-side encryption of {}'.format(DEFAULT_MASTER_ACCT_TF_STATE_BUCKET),
                    KeyUsage='ENCRYPT_DECRYPT',
                    Origin='AWS_KMS',
                    Tags=[
                        {
                            'TagKey': DEFAULT_MASTER_ACCT_TF_STATE_TAG,
                            'TagValue': DEFAULT_MASTER_ACCT_TF_STATE_TAG_VALUE
                        },
                    ]
                )
            except ClientError as e:
                print('master account tf state bucket encryption key not created: {}'.format(e.response['Error']['Code']))
                return False
            try:
                response = kms.create_alias(
                    AliasName=DEFAULT_MASTER_ACCT_TF_STATE_KMS_KEY_ALIAS,
                    TargetKeyId=key['KeyMetadata']['KeyId']
                )
            except ClientError as e:
                print('master account tf state bucket encryption key alias not created: {}'.format(e.response['Error']['Code']))
                return False
            try:
                response = key.enable_key_rotation(
                    KeyId=key['KeyMetadata']['KeyId']
                )
            except ClientError as e:
                print('master account tf state bucket encryption key auto-rotation not enabled: {}'.format(e.response['Error']['Code']))
                return False
        else:
            print('Unexpected error searching for master account tf state encryption key: {}'.format(e.response['Error']['Code']))
            return False

    # create master account tf state bucket
    s3 = session.client('s3')
    try:
        s3.create_bucket(
            Bucket=DEFAULT_MASTER_ACCT_TF_STATE_BUCKET,
            CreateBucketConfiguration={
                'LocationConstraint': 'us-east-2'
            }
        )
    except ClientError as e:
        if e.response['Error']['Code'] != 'BucketAlreadyOwnedByYou':
            print('Unexpected error creating for master account tf state bucket: {}'.format(e.response['Error']['Code']))
            return False

    # set bucket server-side encryption Enabled
    try:
        s3.put_bucket_encryption(
            Bucket=DEFAULT_MASTER_ACCT_TF_STATE_BUCKET,
            ServerSideEncryptionConfiguration={
                'Rules': [
                    {
                        'ApplyServerSideEncryptionByDefault': {
                            'SSEAlgorithm': 'aws:kms',
                            'KMSMasterKeyID': DEFAULT_MASTER_ACCT_TF_STATE_KMS_KEY_ALIAS
                        }
                    },
                ]
            }
        )
    except ClientError as e:
        print('Unexpected error applying server-side encryption to master account tf state bucket: {}'.format(e.response['Error']['Code']))
        return False

    # set bucket versioning Enabled
    try:
        s3.put_bucket_versioning(
            Bucket=DEFAULT_MASTER_ACCT_TF_STATE_BUCKET,
            VersioningConfiguration={
                'Status': 'Enabled'
            }
        )
    except ClientError as e:
        print('Unexpected error enabling versioning on master account tf state bucket: {}'.format(e.response['Error']['Code']))
        return False

    # set public_access_block on bucket
    try:
        s3.put_public_access_block(
            Bucket=DEFAULT_MASTER_ACCT_TF_STATE_BUCKET,
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True
            }
        )
    except ClientError as e:
        print('Unexpected error enabling public_access_block on master account tf state bucket: {}'.format(e.response['Error']['Code']))
        return False
    # there are no tests at this point since each action will either succeed or report failure statue
    # however, this bucket should be included in recurring state tests as they are initiated
