from invoke import task

# the openssl public key for the piipeline, used to encode encryption keys
PUBLIC_ASC='~/.circleci/public/pipeline-public.pem'
PRIVATE_ASC='~/.circleci/private/private.pem'

@task
def encfile(ctx, decoded):
    """encrypt file using local encryption key"""
    ctx.run('openssl enc -aes-256-cbc -md sha512 -salt -in {0} -out {0}.enc -pass file:./key.bin'.format(decoded))
    ctx.run('sha256sum {0}.enc > {0}.enc.sha'.format(decoded))

@task
def enckey(ctx):
    """generate random 2048bit random key to use for encrypting secure files for this pipeline"""
    ctx.run('openssl rand -base64 32 > key.bin')
    ctx.run('openssl rsautl -encrypt -inkey {} -pubin -in key.bin -out key.bin.enc'.format(PUBLIC_ASC))
    ctx.run('sha256sum key.bin.enc > key.bin.enc.sha')

@task
def decfile(ctx, filename):
    """decrypt file encryption key with private.pem and decode file using local encryption key"""
    ctx.run('sha256sum --check --status key.bin.enc.sha')
    ctx.run('openssl rsautl -decrypt -inkey {} -in key.bin.enc -out key.bin'.format(PRIVATE_ASC))
    ctx.run('sha256sum --check --status {}.enc.sha'.format(filename))
    ctx.run('openssl enc -d -aes-256-cbc -md sha512 -in {0}.enc -out {0} -pass file:./key.bin'.format(filename))
