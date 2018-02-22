#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json
import zlib
import argparse
import logging
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization,hashes
from cryptography.hazmat.primitives.asymmetric import padding
import telethon
from pymongo import MongoClient

SECRETS_ROOT = '/etc/drouz'
SESSIONS_ROOT = '/etc/drouz/sessions'

logging.basicConfig(level=logging.DEBUG)


def parse_args():
    return None


def read_config():
    env = os.environ['DROUZ_ENVIRONMENT']
    logging.debug('Environment: {}'.format(env))
    with open(SECRETS_ROOT + '/secrets-{}.yml'.format(env)) as f:
        return json.load(f)


def encrypt_dict(d):
    encrypted_d = {}
    for k, v in d.items():
        print(str(k) + ':' + str(v))
        if type(v) is str or \
           type(v) is int:
            if type(v) is str:
                bytes_v = bytes(v, 'utf-8')
            elif type(v) is int:
                bytes_v = v.to_bytes((v.bit_length() + 7) // 8, 'big') or b'\0'
                encrypted_d[k] = data_encryption_key_public.encrypt(
                    zlib.compress(bytes_v, 9),
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA1()),
                        algorithm=hashes.SHA1(),
                        label=None
                    )
                )
        elif type(v) is dict:
            encrypted_d[k] = encrypt_dict(v)
        else:
            encrypted_d[k] = v

    return encrypted_d


def event_handler(event):
    event_dict = event.to_dict()
    print(event_dict)
    event_dict_encrypted = encrypt_dict(event_dict)
    mongo_db.event_log.insert_one(event_dict_encrypted)
    print(event_dict_encrypted)
    print('Press Enter to stop this!')


def main():
    args = parse_args()
    config = read_config()

    # Connect to telegram
    global telegram_client
    telegram_client = telethon.TelegramClient(
        SESSIONS_ROOT + '/' + config['session'],
        config['telegram_auth']['api_id'],
        config['telegram_auth']['api_hash'],
        use_ipv6=False,
        update_workers=32,
    )
    telegram_client.connect()


    # Connect to mongo
    mongo_client = MongoClient(
        host=config['mongo_auth']['hosts'],
        w=config['mongo_auth']['w'],
        username=config['mongo_auth']['username'],
        password=config['mongo_auth']['password'],
        authSource=config['mongo_auth']['authentication_database'],
        replicaSet=config['mongo_auth']['replica_set'],
        ssl=True,
    )
    global mongo_db
    mongo_db = mongo_client[config['mongo_auth']['database']]

    # Get rsa encryption key
    global data_encryption_key_private
    data_encryption_key_private = serialization.load_pem_private_key(
        bytes(config['data_encryption']['key_private'], 'utf-8'),
        password=None, backend=default_backend(),
    )
    global data_encryption_key_public
    data_encryption_key_public = data_encryption_key_private.public_key()
    encrypted = data_encryption_key_public.encrypt(
        zlib.compress(b"sdfsdf", 9),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )
    print(encrypted)

    decrypted = data_encryption_key_private.decrypt(
        encrypted,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )

    print(zlib.decompress(decrypted))

    try:
        if not telegram_client.is_user_authorized():
            telegram_client.send_code_request(
                config['telegram_auth']['telephone_number']
            )
            telegram_client.sign_in(
                config['telegram_auth']['telephone_number'],
                input('Enter code: ')
            )
        print(telegram_client.get_me())
        telegram_client.add_event_handler(event_handler, telethon.events.Raw)
        input('Press Enter to stop this!\n')
        telegram_client.disconnect()
    except:
        telegram_client.disconnect()
        raise


if __name__ == "__main__":
    main()
