#!/usr/bin/env python3

import argparse
import logging
import os
import subprocess
import shutil
import sys
import tarfile
import tempfile

import gpg

VERSION = '0.1.0'

logger = logging.getLogger('rehydrated')


class Hook:
    _STORE = []

    @classmethod
    def register(cls, name):
        def decorator(func):
            cls._STORE.append((name, func))
            return func
        return decorator

    @classmethod
    def dispatch(cls, name, args):
        for reg_name, func in cls._STORE:
            if name == reg_name:
                func(*args)


def _run(args, **kwargs):
    proc = subprocess.run(args,
                          stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE,
                          **kwargs)
    try:
        proc.check_returncode()
    except subprocess.CalledProcessError as exc:
        print(str(exc), file=sys.stderr)
        print(proc.stderr.decode(), file=sys.stderr)


def _get_env_var_list(env_var_name, split_by=',', strip_comments=True):
    env_var = os.environ.get(env_var_name, None)
    if env_var is None:
        return []
    else:
        # split and strip
        values = [value.strip() for value in env_var.split(split_by)]
        # remove comments starting with a hash
        if strip_comments:
            values = [value.split('#')[0].strip() for value in values]
        # filter non-empty values and return
        return [value for value in values if value]


def _call_hooks(chained_hooks, name, args):
    for script in chained_hooks:
        _run([script, name, *args])
    Hook.dispatch(name, args)


def _encrypt(recipients, file_name, home=None):
    gpg_home = os.path.join(home, 'gpg')
    tmp_home = os.path.join(home, 'tmp')
    context = gpg.Context(armor=True, home_dir=gpg_home)
    recipient_keys = []
    for recipient in recipients:
        recipient_keys.extend(context.keylist(pattern=recipient, secret=False))

    with open(file_name, 'rb') as plain_text, \
            tempfile.NamedTemporaryFile(dir=tmp_home, delete=False) as encrypted_file:
        result, _, _ = context.encrypt(plain_text.read(), recipients=recipient_keys,
                                       sign=False, always_trust=True)
        encrypted_file.write(result)
    os.unlink(file_name)
    return encrypted_file.name


def deploy(home, dest_file, key_file, chain_file, perms=None, encrypt=None):
    tmp_home = os.path.join(home, 'tmp')

    with tempfile.NamedTemporaryFile(mode='wb', delete=False, dir=tmp_home) as data:
        with tarfile.TarFile(fileobj=data, mode='w') as result_file:
            result_file.add(os.path.realpath(key_file), 'key.pem')
            result_file.add(os.path.realpath(chain_file), 'cert.pem')
            result_file_name = result_file.name

    if encrypt:
        result_file_name = encrypt(result_file_name)

    if perms:
        os.chmod(result_file_name, perms)

    shutil.move(result_file_name, dest_file)


def _get_args():
    parser = argparse.ArgumentParser('rehydrated',
                                     description='rehydrated is a dehydrated hook that supports '
                                                 'chain-execution of other hooks and deploys '
                                                 'domain certificates and keys as gpg-encrypted '
                                                 'tar files for distribution.')
    parser.add_argument('hook_name')
    parser.add_argument('hook_arg', nargs=argparse.REMAINDER)
    parser.add_argument('--client', action='append', dest='clients',
                        default=_get_env_var_list('REHYDRATED_CLIENTS'),
                        help='Client GPG key patterns used to encrypt the TLS certificate '
                             'and key. Multiple occurrences are allowed. Can also be set '
                             'via the REHYDRATED_CLIENTS environment variable. When using '
                             'the environment variable you can use commas to separate multiple '
                             'clients. It’s recommended to use fingerprints as pattern, but '
                             'you may also use domains (i.e. `@example.com`) to encrypt exports '
                             'for all known users with a @example.com email-address.')
    parser.add_argument('--home',
                        default=os.environ.get('REHYDRATED_HOME', '/var/lib/rehydrated'),
                        help='Base directory for storing generated files. Can also be '
                             'set via the REHYDRATED_HOME environment variable.')
    parser.add_argument('--export-dir',
                        default=os.environ.get('REHYDRATED_EXPORT_DIR', 'export'),
                        help='Name of the export directory inside home (not a path). Can also '
                             'be set via the REHYDRATED_EXPORT_DIR environment variable. '
                             'Defaults to `export`.')
    parser.add_argument('--export-permissions', type=lambda v: int(v, 8),
                        default=os.environ.get('REHYDRATED_EXPORT_PERMISSIONS', 0o644),
                        help='Filesystem permissions for exported files. Can also be set via the '
                             'REHYDRATED_EXPORT_PERMISSIONS environment variable. '
                             'Defaults to 644. Only octal numbers are supported.')
    parser.add_argument('--should-export', action='store_true',
                        default=os.environ.get('REHYDRATED_SHOULD_EXPORT', '0') == '1',
                        help='Defines if rehydrated should export the key and certificate'
                             'of the current domain. Can also be set via the '
                             'REHYDRATED_SHOULD_EXPORT environment variable. Defaults to '
                             'false to prevent any accidental private key leaks.')
    parser.add_argument('--chained-hook', action='append', dest='chained_hooks', metavar='HOOK',
                        default=_get_env_var_list('REHYDRATED_HOOKS'),
                        help='Hook scripts that should be called before rehydrated’s actions. '
                             'Multiple occurrences are allowed. Can also be set via the '
                             'REHYDRATED_HOOKS environment variable.')
    return parser.parse_args()


def main():
    cli_args = _get_args()

    for subdir, mode in (('tmp', 0o700), ('gpg', 0o700), (cli_args.export_dir, 0o755)):
        path = os.path.join(cli_args.home, subdir)
        if not os.path.isdir(path):
            os.makedirs(os.path.join(cli_args.home, subdir), mode=mode)

    def _maybe_encrypt(file_name, domain):
        if cli_args.clients:
            return _encrypt(cli_args.clients, file_name, cli_args.home)
        else:
            logger.warning('Not encrypting deployment file for domain "{}". '
                           'This is a security risk.'.format(domain))
            return file_name

    if cli_args.should_export:
        @Hook.register('deploy_cert')
        def _deploy(domain, key_file, certfile, full_chain_file, chain_file, timestamp, *args):
            dest_file = os.path.join(cli_args.home, cli_args.export_dir, '{}.tar'.format(domain))
            deploy(cli_args.home, dest_file, key_file, full_chain_file,
                   perms=cli_args.export_permissions,
                   encrypt=lambda file_name: _maybe_encrypt(file_name, domain))

    _call_hooks(cli_args.chained_hooks, cli_args.hook_name, cli_args.hook_arg)


if __name__ == '__main__':
    main()
