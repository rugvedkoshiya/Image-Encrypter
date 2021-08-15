from PIL import Image
import json
import hashlib
import os
from termcolor import cprint 
from pyfiglet import figlet_format
import base64
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto import Random
import uuid
import time


def rgb2hex(rgb):
    return "{:02x}{:02x}{:02x}".format(rgb[0],rgb[1],rgb[2])


def hex2rgb(hexcode):
    return (int(hexcode[0:2], 16), int(hexcode[2:4], 16), int(hexcode[4:6], 16))


def convert_to_rgb_mode(img):
    try:
        rgba_image = img
        rgba_image.load()
        background = Image.new("RGB", rgba_image.size, (255, 255, 255))
        background.paste(rgba_image, mask = rgba_image.split()[3])
        print("[yellow]Converted image to RGB [/yellow]")
        return background
    except Exception as e:
        print(e)
        print("[red]Couldn't convert image to RGB [/red]- %s"%e)


def img_to_rgb_list(img):
    rgb_list = []
    for i in range(0,img.size[0]):
        for j in range(0,img.size[1]):
            color = img.getpixel((j,i))
            for k in range(0,3):
                rgb_list.append(color[k])
    return rgb_list


def img_to_hex(img):
    hex_str = ""
    for i in range(0,img.size[0]):
        for j in range(0,img.size[1]):
            color = img.getpixel((j,i))
            hex_str += rgb2hex(color)
    return hex_str


def hex_list_to_rgb_list(img_hex_data_list):
    rgb_list = []
    for hex in img_hex_data_list:
        color = hex2rgb(hex)
        for k in range(0,3):
            rgb_list.append(color[k])
    return rgb_list


def get_hash_from_rgb_list(rgb_list, img_size):
    sha256_hash = hashlib.sha256()
    img2 = Image.frombytes('RGB', (img_size[0],img_size[1]), bytes(rgb_list), 'raw')
    filename = str(uuid.uuid4().hex + ".jpg")
    img2.save(filename)
    with open(filename, "rb") as file:
        for byte_block in iter(lambda: file.read(4096),b""):
            sha256_hash.update(byte_block)
    os.remove(filename)
    return sha256_hash.hexdigest()


def convert_to_json(sha256, size, data):
    data_json = {
        "time": int(time.time()),
        "sha256": sha256,
        "size": [size[0], size[1]],
        "data": data,
    }
    return json.dumps(data_json, separators=(',', ':'))


def create_valid_hex_list(str_hex_data):
    hex_list = []
    for hex_val in range(0, len(str_hex_data), 6):
        hex_list.append(str_hex_data[hex_val:hex_val+6])
    return hex_list


def create_img_from_rgb_list(rgb_list, img_size, img_hash):
    img2 = Image.frombytes('RGB', (img_size[0],img_size[1]), bytes(rgb_list), 'raw')
    img2.save(img_hash + ".jpg")


def encrypt_img_data(key, source, encode=True):
    key = SHA256.new(key).digest()
    IV = Random.new().read(AES.block_size)
    encryptor = AES.new(key, AES.MODE_CBC, IV)
    padding = AES.block_size - len(source) % AES.block_size
    source += bytes([padding])*padding
    data = IV + encryptor.encrypt(source)
    return base64.b64encode(data).decode() if encode else data


def decrypt_img_data(key, source, decode=True):
    if decode:
        source = base64.b64decode(source.encode())
    key = SHA256.new(key).digest()
    IV = source[:AES.block_size]
    decryptor = AES.new(key, AES.MODE_CBC, IV)
    data = decryptor.decrypt(source[AES.block_size:])
    padding = data[-1]
    if data[-padding:] != bytes([padding])*padding:
        raise ValueError("Invalid padding...")
    return data[:-padding].decode() if decode else data[:-padding]


def main():
    try:
        print("[cyan]Choose one: [/cyan]")
        encode_decode_option = input("1. Encode\n2. Decode\n>>")
        if encode_decode_option != "":
            try:
                encode_decode_option = int(encode_decode_option)
            except:
                raise Exception("wrong_option")
        else:
            raise Exception("no_option")

        if encode_decode_option == 1:
            print("[cyan]Image path (with extension): [/cyan]")
            img_path = input(">>")
            if(not(os.path.exists(img_path))):
                raise Exception("path_error")

            img = Image.open(img_path)
            if img.mode != 'RGB':
                img = convert_to_rgb_mode(img)
                img = img.copy()

            img_hex_data_str = img_to_hex(img)
            img_rgb_list = img_to_rgb_list(img)
            img_hash = get_hash_from_rgb_list(img_rgb_list, img.size)

            img_hex_encrypted_data_str = encrypt_img_data(key=img_hash.encode(),source=img_hex_data_str.encode())
            json_data = convert_to_json(img_hash, img.size, img_hex_encrypted_data_str)

            with open(f"{img_hash}.json", "w") as file:
                file.write(json_data)

        elif encode_decode_option == 2:
            print("[cyan]Image path (with extension): [/cyan]")
            img_path = input(">>")
            if(not(os.path.exists(img_path))):
                raise Exception("path_error")

            with open(img_path, "r") as file:
                jsonFile = json.load(file)
            img_hash = jsonFile["sha256"]
            img_size = jsonFile["size"]
            img_hex_encrypted_data_str = jsonFile["data"]
            img_decrypted_data_str = decrypt_img_data(key=img_hash.encode(),source=img_hex_encrypted_data_str)

            img_hex_list = create_valid_hex_list(img_decrypted_data_str)
            img_rgb_list = hex_list_to_rgb_list(img_hex_list)
            create_img_from_rgb_list(img_rgb_list, img_size, img_hash)

    except Exception as error:
        if type(error) == type(Exception("no_option")) and error.args == Exception("no_option").args:
            print("[red]No option choose by you :([/red]")
        elif type(error) == type(Exception("wrong_option")) and error.args == Exception("wrong_option").args:
            print("[red]Wrong[/red] option choose by you :(")
        elif type(error) == type(Exception("path_error")) and error.args == Exception("path_error").args:
            print("Image Not Found!")
        print(error)







if __name__ == "__main__":
    os.system('cls' if os.name == 'nt' else 'clear')
    cprint(figlet_format('Mr Grey', font='starwars'),'yellow', attrs=['bold'])
    print("This tool allows you to encode an image, you can also protect your image using AES-256.")
    print()

    main()