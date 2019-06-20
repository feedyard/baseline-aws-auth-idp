"""invoke tasks for the feedyard/bootstrap-aws resource"""
from invoke import Collection
from tasks import deploy
from tasks import delete
from tasks import idp
from tasks import openssl
from tasks import gpg

ns = Collection()
ns.add_collection(deploy)
ns.add_collection(delete)
ns.add_collection(idp)
ns.add_collection(openssl)
ns.add_collection(gpg)