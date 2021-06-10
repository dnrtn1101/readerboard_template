import json
from base64 import b64encode
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad


def read_txt(fileName):
    with open(fileName, 'rt') as f:
        list_data = list(f.readlines())
    return list_data


def write_json(fileName, data):
    with open(fileName, 'w') as f:
        json.dump(data, f, ensure_ascii=False, indent=4)


def load_key(key_path):
    with open(key_path, "rb") as f:
        key = f.read()
    return key


def encrypt_data(key_path, ans_list, encrypt_store_path='ans.json'):
    key = load_key(key_path)
    data = " ".join([str(i) for i in ans_list])
    encode_data = data.encode()
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(encode_data, AES.block_size))
    iv = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    write_json(encrypt_store_path, {'iv': iv, 'ciphertext': ct})


if __name__ == "__main__":



    key_path = "201920785.pem"
    raw_ans_path = "ans18.txt"

    ans = read_txt(raw_ans_path)

    encrypt_ans_path = "../submission/201920785/ans.json"
    encrypt_data(key_path, ans, encrypt_ans_path)

