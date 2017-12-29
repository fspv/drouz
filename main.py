#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import yaml
import zlib
import argparse
import logging
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization,hashes
from cryptography.hazmat.primitives.asymmetric import padding
import telethon
from pymongo import MongoClient

logging.basicConfig(level=logging.DEBUG)

def parse_args():
    return None


def read_config():
    with open('secrets.yml') as f:
        return yaml.load(f.read())


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


def update_handler(update):
    update_dict = update.to_dict()
    print(update_dict)
    update_dict_encrypted = encrypt_dict(update_dict)
    mongo_db.update_log.insert_one(update_dict_encrypted)
    print(update_dict_encrypted)
    print('Press Enter to stop this!')


def main():
    args = parse_args()
    config = read_config()

    # Connect to telegram
    global telegram_client
    telegram_client = telethon.TelegramClient(
        config['session'],
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
        telegram_client.add_update_handler(update_handler)
        input('Press Enter to stop this!\n')
        telegram_client.disconnect()
    except:
        telegram_client.disconnect()
        raise


if __name__ == "__main__":
    main()
