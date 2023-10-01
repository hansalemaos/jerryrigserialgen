import itertools
import operator
import random
import tempfile
import xxhash
import requests
from isiter import isiter
from touchtouch import touch
import math
import os
from time import time, strftime, perf_counter
import dill
import sys
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad

ver = sys.version_info
out = sys.stdout.flush
import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
serialgenconfig = sys.modules[__name__]
serialgenconfig.transfershdomain = 'https://transfer.sh'


def iter_get_random_values_with_max_rep(list_, howmany, maxrep):
    resi = []
    resistr = []
    numbers = list_
    alldi = {f"{repr(x)}{x}": x for x in numbers}
    numbersdi = {}
    for ma in range(maxrep):
        for key, item in alldi.items():
            numbersdi[f"{key}{ma}"] = item
    if (h := len(numbersdi.keys())) < howmany:
        raise ValueError(f"choices: {howmany} / unique: {h}")
    while len(resi) <= howmany - 1:
        [
            (resi.append(numbersdi[g]), resistr.append(g))
            for x in range(len(numbers))
            if len(resi) <= howmany - 1
            and (g := random.choice(tuple(set(numbersdi.keys()) - set(resistr))))
            not in resistr
        ]
    return resi


list_ = [hex(x)[2:] for x in list(range(0, 16))]
howmany = 32
maxrep = 4
signature_hex = "".join(iter_get_random_values_with_max_rep(list_, howmany, maxrep))
byx = bytes.fromhex(signature_hex)
keyba = base64.encodebytes(byx)


def get_rsa_keys():
    # Generate an RSA key pair
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pri = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pri, pub


def hex_to_str(x):
    return "".join([chr(int(x[i : i + 2], 16)) for i in range(0, len(x), 2)])


def str_to_hex(s):
    return "".join([("0" + hex(ord(c)).split("x")[1])[-2:] for c in s])


def create_license(message, keyba):

    key = base64.decodebytes(keyba)
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode("utf-8"))
    encrypted_key = base64.b64encode(ciphertext + tag).decode("utf-8")
    decoded_key = base64.b64decode(encrypted_key)
    ciphertext = decoded_key[:-16]  # The last 16 bytes are the tag
    tag = decoded_key[-16:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=cipher.nonce)
    original_message = cipher.decrypt(ciphertext).decode("utf-8")
    return ciphertext, tag, original_message, encrypted_key, key, cipher


def check(encrypted_key, cipher, ciphertext, keyba):
    key = base64.decodebytes(keyba)

    decoded_key = base64.b64decode(encrypted_key)
    ciphertext = decoded_key[:-16]
    cipher = AES.new(key, AES.MODE_EAX, nonce=cipher.nonce)
    original_message = cipher.decrypt(ciphertext).decode("utf-8")
    return original_message


def get_k(myprod, keyba):
    ciphertext, tag, original_message, encrypted_key, key, cipher = create_license(
        myprod, keyba
    )
    a = (
        dill.dumps(
            [
                ciphertext,
                tag,
                original_message,
                encrypted_key,
                key,
            ]
        ),
        cipher,
    )
    serialnumber, b = a
    baaa = base64.b64encode(serialnumber).decode("utf-8")
    return str_to_hex(baaa)


def get_infos_from_serial(serialnumberk, keyba):
    serialnumber = base64.b64decode(hex_to_str(serialnumberk).encode())
    myprod = dill.loads(serialnumber)[2]
    ciphertext, tag, original_message, encrypted_key, key, cipher = create_license(
        myprod, keyba
    )
    orgmessage = check(encrypted_key, cipher, ciphertext, keyba)
    p, d, ts, otherinformation = original_message.split("####")
    d = int(d)
    ts = int(ts)
    duid = {}
    duid["ciphertext"] = ciphertext
    duid["tag"] = tag
    duid["original_message"] = original_message
    duid["encrypted_key"] = encrypted_key
    duid["key"] = key
    duid["cipher"] = cipher
    duid["orgmessage"] = orgmessage
    duid["days"] = d
    duid["timestamp"] = ts
    duid["daysleft"] = math.ceil(((duid["timestamp"] + d * 86400) - time()) / 86400)
    duid["product"] = p
    duid["otherinformation"] = otherinformation
    duid["cipher"] = duid["cipher"].__dict__["nonce"]
    return duid


def start_license_generator(
    product, limit, otherinformation, output, subtract_from_time, keyba
):

    myprod = f"{product}####{limit}####{str(math.floor(time())-int(subtract_from_time))}####{otherinformation}"
    serialnumberk = get_k(myprod, keyba)
    duid = get_infos_from_serial(serialnumberk, keyba)

    filename = os.path.normpath(output)
    with open(filename, mode="w", encoding="utf-8") as f:
        f.write(serialnumberk.strip())

    print(f"File written to: {filename}")

    return myprod, duid, serialnumberk


def get_tmpfile(suffix=".bat"):
    tfp = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
    filename = tfp.name
    filename = os.path.normpath(filename)
    tfp.close()
    touch(filename)
    return filename


def upload_file_to_transfer(filepath, password=None, maxdownloads=1):
    if password:
        headers = {
            "Max-Downloads": str(maxdownloads),
            #"X-Encrypt-Password": password,
        }
    else:
        headers = {"Max-Downloads": str(maxdownloads)}

    fileonly = filepath.split(os.sep)[-1]
    with open(filepath, "rb") as f:
        data = f.read()
    response = requests.put(
        f"{serialgenconfig.transfershdomain.rstrip('/')}/{fileonly}", headers=headers, data=data
    )
    newlink = response.content.decode("utf-8", "ignore")
    return newlink


def write_message_to_hd(message):
    bintmpfile = get_tmpfile(suffix=".bin")
    with open(bintmpfile, mode="wb") as f:
        f.write(message)
    return bintmpfile


def get_file_hash(filepath):
    with open(filepath, "rb") as f:
        file_hash = xxhash.xxh3_128()
        while chunk := f.read(8192):
            file_hash.update(chunk)
        hexdig = file_hash.hexdigest()
        return hexdig


def get_filename(folder):

    timestamp = (
        lambda: str(strftime("%Y_%m_%d_%H_%M_%S"))
        + "_"
        + str(perf_counter()).replace(".", "")
        + ".cfg"
    )
    cfgfilename = timestamp()
    newfiname = os.path.normpath(os.path.join(folder, cfgfilename))
    touch(newfiname)
    forclient = newfiname[:-4] + ".txt"
    touch(forclient)
    return newfiname, forclient


class Cryptor:
    # https://stackoverflow.com/a/75713952/15096247
    def __init__(self, key):
        self.SECRET_KEY = str(key).encode("utf-8")
        self.BLOCK_SIZE = 32
        self.CIPHER = AES.new(self.SECRET_KEY, AES.MODE_ECB)

    def encrypt(self, text):
        text = str(text).encode("utf-8")
        return base64.b64encode(self.CIPHER.encrypt(pad(text, self.BLOCK_SIZE))).decode(
            "utf-8"
        )

    def decrypt(self, encoded_text):
        self.CIPHER = AES.new(self.SECRET_KEY, AES.MODE_ECB)
        return unpad(
            self.CIPHER.decrypt(base64.b64decode(encoded_text)), self.BLOCK_SIZE
        ).decode("utf-8")


def joinall(s, iterable):
    if len(iterable) == 0:
        return ""
    if len(iterable) == 1:
        return str(iterable[0])
    sese = str(s)
    sta = tuple(
        itertools.accumulate(map(str, iterable), lambda a, b: operator.add(a, b) + sese)
    )[-1]
    sta = sta[: -len(sese)]
    sta = f"{sta[:len(str(iterable[0]))]}{sese}{sta[len(str(iterable[0])):]}"
    return sta


class Serialgenerator:
    def __init__(
        self,
        product,
        savefolder,
        hardcodedpasswort_transfer,
        hardcodedpasswort_url, addinformationtoserial=(),

            licensedays=30,
        subtract_from_time=0,
    ):
        if not isiter(addinformationtoserial):
            addinformationtoserial = [addinformationtoserial]
        self.publicrsa, self.privatersa = get_rsa_keys()
        self.limit = licensedays
        self.product = product
        # folder to save generated license files
        self.folder = savefolder
        self.licensefileonhdd, self.forclient = get_filename(self.folder)
        self.subtract_from_time = subtract_from_time
        # hardcoded hardcodedpasswort_transfer in software (for transfer.sh)
        self.password = hardcodedpasswort_transfer

        # save as bin file
        self.filepath = write_message_to_hd(self.publicrsa)

        # make the file hash part of the serial number
        filehash = get_file_hash(self.filepath)

        # upload to transfer.sh - file will be deleted after the first download, link is enctypted and part of the serial number
        newlink = upload_file_to_transfer(
            self.filepath, password=self.password, maxdownloads=1
        )

        # myprod = decoded serial
        # duid = decoded serial as dict
        # serialnumberk = serial for the client
        addinformationtoserialstr = joinall("ÇÇÇ", addinformationtoserial)
        self.otherinformation = (
            f"{newlink}ÇÇÇ{filehash}ÇÇÇ{self.privatersa.decode('utf-8')}"
        )
        if len(addinformationtoserialstr) > 0:
            self.otherinformation = (
                f"{self.otherinformation}ÇÇÇ{addinformationtoserialstr}"
            )
        self.myprod, self.duid, self.serialnumberk = start_license_generator(
            product=self.product,  # name of the product
            limit=self.limit,  # time limit
            otherinformation=self.otherinformation,  # other information you need to be on the clients pc
            output=self.licensefileonhdd,
            subtract_from_time=subtract_from_time,
            keyba=keyba,
        )

        with open(self.forclient, mode="w", encoding="utf-8") as f:
            f.write(self.serialnumberk)

        self.hardcodedurldec = hardcodedpasswort_url

    def upload(self):
        self.registered_product = self.duid["product"]
        self.registered_timestamp = self.duid["timestamp"]
        self.registered_days = self.duid["days"]
        self.registered_daysleft = self.duid["daysleft"]

        linkforclient = upload_file_to_transfer(
            self.forclient, password=self.password, maxdownloads=1
        )

        cryptor = Cryptor(self.hardcodedurldec)
        text = cryptor.encrypt(linkforclient)
        text = str_to_hex(text)
        returninfos = {
            "product": self.registered_product,
            "purchase": self.registered_timestamp,
            "duration": self.registered_days,
            "days_left": self.registered_daysleft,
            "serial_number ": text + signature_hex,
            "signature_hex": signature_hex,
            "content_of_second_file": self.serialnumberk,
            "uploaded_file_on_local_HDD ": self.forclient,
            "decrypted_serial_number ": cryptor.decrypt(hex_to_str(text)),
        }
        print(returninfos)
        return text + signature_hex, returninfos

