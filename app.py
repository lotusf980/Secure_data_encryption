import streamlit as st
import hashlib
import json
import os
from cryptography.fernet import Fernet
from datetime import datetime, timedelta

# --------- Configurations ---------
KEY = Fernet.generate_key()
cipher = Fernet(KEY)
DATA_FILE = "data.json"
LOCKOUT_FILE = "lockout.json"
LOCKOUT_DURATION = timedelta(minutes=1)
MASTER_PASSWORD = "kanwalumer"

# --------- Load & Save Functions ---------
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as file:
            return json.load(file)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as file:
        json.dump(data, file)

def load_lockout():
    if os.path.exists(LOCKOUT_FILE):
        with open(LOCKOUT_FILE, "r") as file:
            return json.load(file)
    return {}

def save_lockout(lockout):
    with open(LOCKOUT_FILE, "w") as file:
        json.dump(lockout, file)

# --------- Utility Functions ---------
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, passkey):
    hashed = hash_passkey(passkey)
    for key, value in st.session_state.stored_data.items():
        if key == encrypted_text and value["passkey"] == hashed:
            st.session_state.failed_attempts = 0
            st.session_state.lockout_time = None
            return cipher.decrypt(encrypted_text.encode()).decode()
    st.session_state.failed_attempts += 1
    if st.session_state.failed_attempts >= 3:
        st.session_state.lockout_time = datetime.now().isoformat()
        save_lockout({"time": st.session_state.lockout_time})
    return None

# --------- Streamlit Session State ---------
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = load_data()
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'lockout_time' not in st.session_state:
    lock_data = load_lockout()
    st.session_state.lockout_time = lock_data.get("time")
if 'is_authenticated' not in st.session_state:
    st.session_state.is_authenticated = False

# --------- Lockout Check ---------
if st.session_state.lockout_time:
    lockout_time = datetime.fromisoformat(st.session_state.lockout_time)
    if datetime.now() < lockout_time + LOCKOUT_DURATION:
        st.warning("⏳ You're locked out due to too many failed attempts. Try again later.")
        st.stop()
    else:
        st.session_state.failed_attempts = 0
        st.session_state.lockout_time = None
        save_lockout({})

# --------- Page Functions ---------
def home_page():
    st.subheader("🏠 Welcome to the Secure Data System")
    st.markdown("Use this app to **securely store and retrieve your data** using a unique passkey.")

def store_data_page():
    st.subheader("📂 Store Data Securely")
    user_data = st.text_area("Enter Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            encrypted_text = encrypt_data(user_data)
            hashed_pass = hash_passkey(passkey)
            st.session_state.stored_data[encrypted_text] = {
                "encrypted_text": encrypted_text,
                "passkey": hashed_pass
            }
            save_data(st.session_state.stored_data)
            st.success("✅ Data encrypted and stored successfully!")
            st.code(encrypted_text, language="text")
        else:
            st.error("⚠️ Both fields are required!")

def retrieve_data_page():
    st.subheader("🔍 Retrieve Your Data")
    encrypted_text = st.text_area("Enter Encrypted Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_text and passkey:
            result = decrypt_data(encrypted_text, passkey)
            if result:
                st.success("✅ Decrypted Data:")
                st.code(result, language="text")
            else:
                attempts_left = max(0, 3 - st.session_state.failed_attempts)
                st.error(f"❌ Incorrect passkey! Attempts remaining: {attempts_left}")

                if st.session_state.failed_attempts >= 3:
                    st.warning("🔒 Too many failed attempts! Please login again.")
                    st.experimental_rerun()
        else:
            st.error("⚠️ Both fields are required!")

def login_page():
    st.subheader("🔑 Reauthorization Required")
    login_pass = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if login_pass == MASTER_PASSWORD:
            st.session_state.failed_attempts = 0
            st.session_state.lockout_time = None
            st.session_state.is_authenticated = True
            save_lockout({})
            st.success("✅ Login successful! You can now retry decryption.")
        else:
            st.error("❌ Incorrect master password!")

# --------- Navigation ---------
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("📋 Navigation", menu)

if choice == "Home":
    home_page()
elif choice == "Store Data":
    store_data_page()
elif choice == "Retrieve Data":
    if st.session_state.failed_attempts >= 3 and not st.session_state.is_authenticated:
        st.warning("🔒 You must reauthorize before continuing.")
        st.experimental_rerun()
    else:
        retrieve_data_page()
elif choice == "Login":
    login_page()
