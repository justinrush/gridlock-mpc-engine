# Deployment environments

## app.gridlock.network (production)

Currently running on an AWS instance with an IP firewall in place giving SSH access only to developers' IPs. These developers' SSH public keys are listed in `/home/ubuntu/.ssh/authorized_keys` and can execute `sudo` without using a password.

## staging.gridlock.network (staging)

Pretty much same configuration as production, but without the IP firewall on SSH.
