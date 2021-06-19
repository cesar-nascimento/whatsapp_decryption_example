from urllib.request import urlopen
import hmac
import hashlib
from math import ceil
from io import BytesIO
from base64 import b64decode
from typing import Union

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class Decryptor:
    @classmethod
    def hmac_sha256(
        cls,
        key: Union[bytes, bytearray],
        data: bytes,
        digestmod=hashlib.sha256,
    ) -> bytes:
        return hmac.new(key, data, digestmod).digest()

    @classmethod
    def hkdf_expand(
        cls,
        input_key_material: bytes,
        length: int,
        info: bytes = b"",
        digestmod=hashlib.sha256,
    ) -> bytes:
        hash_len = digestmod().digest_size
        if length > 255 * hash_len:
            raise Exception(
                "Cannot expand to more than 255 * {} = {} "
                "bytes using the specified hash function. "
                "Length requested {}.".format(hash_len, 255 * hash_len, length)
            )

        n = ceil(length / hash_len)

        salt = bytearray(32)
        pseudo_random_key = cls.hmac_sha256(salt, input_key_material)

        output_key_material = b""
        output_block = b""
        for index in range(n):
            output_block = cls.hmac_sha256(
                key=pseudo_random_key,
                data=output_block + info + bytes([1 + index]),
            )
            output_key_material += output_block
        return output_key_material[:length]

    @classmethod
    def decrypt(cls, media_url: str, media_key: str, salt: bytes):
        input_key_material = b64decode(media_key)
        media_key_expanded = cls.hkdf_expand(
            input_key_material=input_key_material, length=112, info=salt
        )

        iv = media_key_expanded[:16]
        cipherKey = media_key_expanded[16:48]
        # mac_key = media_key_expanded[48:80]
        # ref_key = media_key_expanded[80:]

        media_data = urlopen(media_url).read()
        my_file = media_data[:-10]
        # mac = media_data[-10:]

        cr_obj = Cipher(
            algorithms.AES(cipherKey), modes.CBC(iv), backend=default_backend()
        )
        decryptor = cr_obj.decryptor()
        return BytesIO(decryptor.update(my_file) + decryptor.finalize())


if __name__ == "__main__":
    media_url = "https://mmg-fna.whatsapp.net/d/f/Ap2hVbW3Da_8idKFxKUVgS7AVbDymv55tXbDVZgCAUE-.enc"
    media_key = "krk2Wig1NNFPZYSBQ0gyuop3Jn2TtjfxEN+XJTefLtA="
    salt = b"WhatsApp Image Keys"

    decoded_image_data = Decryptor.decrypt(media_url, media_key, salt)
    with open("image.jpg", "wb") as f:
        f.write(decoded_image_data.getvalue())

    print("file written")
