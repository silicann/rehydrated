# rehydrated

rehydrated is a [dehydrated](https://github.com/lukas2511/dehydrated) hook that supports 
chain-execution of other hooks and deploys domain certificates and keys as 
gpg-encrypted tar files for distribution.

## The Problem

Even though `dns-01` validation in *Let's Encrypt* brings support for pleasantries such as
wildcard TLS certificate support and intranet transport security without the need for self-signed
certificates, it is somewhat cumbersome to roll-out the required hooks for updating DNS 
entries to various hosts that need TLS certificates, not to say insecure as these hooks
usually contain API keys for domain registrars.

*rehydrated* solves this problem by chain-loading the required `dns-01` validation hook and
encrypting the generated private key and certificate with the target host’s GPG key. The generated
files can be safely distributed with a web-server or via some other medium.

## Requirements

*rehydrated* requires Python 3 and the python-gpg library.

## dehydrated Configuration

*rehydrated* does not provide any mechanism to deploy `dns-01` validation. If you haven’t
configured dehydrated for the `dns-01` challenge type yet, you have to do that now.

Paths in the examples below are somewhat Debian-specific, but should be easy to adapt
to any other operating system supporting dehydrated.

After you’ve done so, you should set a few global dehydrated options:

```bash
# file: /etc/dehydrated/conf.d/local.sh

# when you have installed this package in Debian,
# you should load the system configuration
. /etc/default/rehydrated-hook

# use rehydrated as the primary hook
HOOK=/usr/share/rehydrated-hook/rehydrated-hook-helper
# this is actually evaluated by rehydrated and should point to your original hook
# you can add more than one hook, by separating them with a comma.
export REHYDRATED_HOOKS=/path/to/your/dns-01-hook
```

If you wanted to add a global GPG encryption key you would insert the following line as well:

```bash
# file: /etc/dehydrated/conf.d/local.sh
export REHYDRATED_CLIENTS="21DE48E31212DBB5"  # foo@example.com
```

In case you add a global GPG encryption key you might want to add the following line to
enable encrypted exports for all domains defined in dehydrated:

```bash
# file: /etc/dehydrated/conf.d/local.sh
export REHYDRATED_SHOULD_EXPORT=1
```

Adding individual encryption keys per-domain works with the help of the 
`/etc/rehydrated/domains.conf.d` directory. Example for the `sub.example.com` domain:

```bash
# file: /etc/rehydrated/domains.conf.d/sub.example.com

# encrypt for these consumers:
#   my server <foo@example.com>,
#   this linus guy <torvalds@kernel.org>
export REHYDRATED_CLIENTS="${REHYDRATED_CLIENTS:-}21DE48E31212DBB5,79BE3E4300411886"
# activate rehydrated for this domain
export REHYDRATED_SHOULD_EXPORT=1
```

*rehydrated* also allows you to export keys without encryption though this is
**highly** discouraged. In case you haven’t configured any clients the exported
tar file will not be encrypted.

## Configuration Options

See `src/rehydrated-hook.py --help` for a list of of available options.
