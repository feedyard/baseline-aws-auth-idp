from invoke import task

# the public key for the piipeline, used to encode encryption keys
PIPELINE_ASC='~/.circleci/public/pipeline-public.asc'
PRIVATE_ASC='~/.circleci/private/private.asc'

@task
def encfile(ctx, key, decoded):
    """encrypt file using local encryption key"""
    ctx.run('gpg --encrypt --recipient {0} --output {1}.enc {1}'.format(key, decoded))
    ctx.run('sha256sum {0}.enc > {0}.enc.sha'.format(decoded))

@task
def decfile(ctx, filename, key):
    """decrypt file encryption key with private.pem and decode file using local encryption key"""
    ctx.run('sha256sum --check --status {}.enc.sha'.format(filename))
    ctx.run('gpg --decrypt --output {0}  {0}.enc'.format(filename))
