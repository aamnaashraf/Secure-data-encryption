import streamlit as st
import hashlib
import json
import time
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os

# Configuration
PERSISTENCE_FILE = "encrypted_data.json"
MASTER_PASS_HASH = os.environ.get("MASTER_PASS_HASH", "default_hash")

# Initialize session state
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
if "user_data" not in st.session_state:
    st.session_state.user_data = ""
if "current_page" not in st.session_state:
    st.session_state.current_page = "auth"

# Generate or load encryption key
@st.cache_resource
def get_cipher():
    key = Fernet.generate_key()
    return Fernet(key)

# Password hashing with PBKDF2
def hash_passkey(passkey, salt=None):
    salt = salt or os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(passkey.encode()))
    return key.decode(), salt

# Data persistence
def load_data():
    try:
        with open(PERSISTENCE_FILE, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def save_data(data):
    with open(PERSISTENCE_FILE, "w") as f:
        json.dump(data, f)

# Security functions
def check_lockout():
    if st.session_state.failed_attempts >= 3:
        st.error("🔒 Account locked for 5 minutes due to multiple failed attempts")
        time.sleep(300)
        st.session_state.failed_attempts = 0
        st.session_state.authenticated = False
        st.rerun()

# Custom CSS
def inject_custom_css():
    st.markdown("""
    <style>
    .main {
        background-color: #f8f9fa;
    }
    .sidebar .sidebar-content {
        background-color: #2e4057;
        color: white;
    }
    .stButton>button {
        background-color: #4CAF50;
        color: white;
        border-radius: 5px;
        padding: 0.5rem 1rem;
        transition: all 0.3s;
    }
    .stButton>button:hover {
        background-color: #45a049;
    }
    .stTextInput>div>div>input {
        border-radius: 5px;
        padding: 8px;
    }
    .stTextArea>div>div>textarea {
        border-radius: 5px;
    }
    .info-box {
        background-color: #e7f3fe;
        border-left: 6px solid #2196F3;
        padding: 1rem;
        margin-bottom: 1rem;
        border-radius: 5px;
    }
    .nav-button {
        margin-bottom: 10px;
        width: 100%;
    }
    .footer {
        position: fixed;
        bottom: 0;
        width: 100%;
        text-align: center;
        padding: 10px;
        background-color: #2e4057;
        color: white;
    }
    </style>
    """, unsafe_allow_html=True)

# Authentication Page
def show_auth():
    st.title("🔐 SecureVault Authentication")
    with st.form("auth_form"):
        password = st.text_input("Enter Master Password", type="password")
        if st.form_submit_button("Login"):
            input_hash = hashlib.sha256(password.encode()).hexdigest()
            if input_hash == MASTER_PASS_HASH:
                st.session_state.authenticated = True
                st.session_state.current_page = "home"
                st.rerun()
            else:
                st.error("Incorrect password")

# Navigation Sidebar
def show_sidebar():
    with st.sidebar:
        st.title("🔒 SecureVault")
        st.markdown("---")
        
        if st.button("🏠 Home", key="home_btn", use_container_width=True, 
                   type="primary" if st.session_state.current_page == "home" else "secondary"):
            st.session_state.current_page = "home"
            st.rerun()
            
        if st.button("📥 Store Data", key="store_btn", use_container_width=True,
                   type="primary" if st.session_state.current_page == "store" else "secondary"):
            st.session_state.current_page = "store"
            st.rerun()
            
        if st.button("📤 Retrieve Data", key="retrieve_btn", use_container_width=True,
                   type="primary" if st.session_state.current_page == "retrieve" else "secondary"):
            st.session_state.current_page = "retrieve"
            st.rerun()
            
        st.markdown("---")
        if st.button("🔐 Logout", key="logout_btn", use_container_width=True):
            st.session_state.authenticated = False
            st.session_state.current_page = "auth"
            st.rerun()
        
        st.markdown("""
        <div style="margin-top: 50px;">
            <small>Version 1.0.0</small><br>
            <small>© 2024 SecureVault</small>
        </div>
        """, unsafe_allow_html=True)

# Home Page
def render_home_page():
    st.title("Welcome to SecureVault")
    st.markdown("""
    <div class="info-box">
        <strong>🔒 Military-Grade Encryption</strong><br>
        Store and retrieve sensitive data securely using AES-256 encryption
    </div>
    """, unsafe_allow_html=True)
    
    col1, col2 = st.columns(2)
    with col1:
        with st.container(border=True):
            st.markdown("### 📥 Store New Data")
            st.write("Encrypt and store your sensitive information")
            if st.button("Go to Storage", key="go_store", use_container_width=True):
                st.session_state.current_page = "store"
                st.rerun()

    with col2:
        with st.container(border=True):
            st.markdown("### 📤 Retrieve Data")
            st.write("Access your encrypted data with your passkey")
            if st.button("Go to Retrieval", key="go_retrieve", use_container_width=True):
                st.session_state.current_page = "retrieve"
                st.rerun()

# Store Page
def render_store_page():
    st.title("📥 Store Encrypted Data")
    
    with st.form("store_form"):
        user_data = st.text_area("Data to Encrypt", height=200, 
                               placeholder="Enter your sensitive data here...")
        passkey = st.text_input("Encryption Passphrase", type="password",
                              help="Must be at least 8 characters long")
        
        if st.form_submit_button("🔒 Encrypt & Store"):
            if len(passkey) < 8:
                st.error("Passphrase must be at least 8 characters")
            elif not user_data.strip():
                st.error("Please enter data to encrypt")
            else:
                cipher = get_cipher()
                encrypted = cipher.encrypt(user_data.encode())
                hashed_pass, salt = hash_passkey(passkey)
                
                data = load_data()
                data_id = f"entry_{len(data) + 1}"
                data[data_id] = {
                    "encrypted": encrypted.decode(),
                    "passkey": hashed_pass,
                    "salt": base64.b64encode(salt).decode(),
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                }
                save_data(data)
                
                st.success("✅ Data encrypted successfully!")
                st.code(encrypted.decode(), language="text")
                st.warning("⚠️ IMPORTANT: Copy and save this encrypted text - it cannot be recovered if lost!")
                st.session_state.user_data = ""

# Retrieve Page
def render_retrieve_page():
    st.title("📤 Retrieve Encrypted Data")
    
    with st.form("retrieve_form"):
        encrypted = st.text_area("Encrypted Text", height=150,
                               placeholder="Paste your encrypted data here...")
        passkey = st.text_input("Decryption Passphrase", type="password",
                              help="Enter the same passphrase used during encryption")
        
        if st.form_submit_button("🔓 Decrypt"):
            if not encrypted.strip() or not passkey.strip():
                st.error("Both fields are required")
                return
                
            data = load_data()
            cipher = get_cipher()
            
            for entry_id, entry in data.items():
                if entry["encrypted"] == encrypted:
                    try:
                        salt = base64.b64decode(entry["salt"])
                        hashed_pass, _ = hash_passkey(passkey, salt)
                        
                        if hashed_pass == entry["passkey"]:
                            decrypted = cipher.decrypt(entry["encrypted"].encode())
                            st.session_state.failed_attempts = 0
                            st.success("✅ Decryption successful!")
                            st.code(decrypted.decode(), language="text")
                            st.info(f"📅 Originally stored on: {entry.get('timestamp', 'unknown')}")
                            return
                    except Exception as e:
                        st.error(f"❌ Decryption error: {str(e)}")
                        return
            
            st.session_state.failed_attempts += 1
            st.error(f"❌ Invalid passphrase (Attempt {st.session_state.failed_attempts}/3)")
            check_lockout()

# Main App
def main():
    set_page_config()
    inject_custom_css()
    
    if not st.session_state.authenticated:
        show_auth()
    else:
        show_sidebar()
        
        if st.session_state.current_page == "home":
            render_home_page()
        elif st.session_state.current_page == "store":
            render_store_page()
        elif st.session_state.current_page == "retrieve":
            render_retrieve_page()
        
        # Footer
        st.markdown("""
        <div class="footer">
            <small>🔒 All data is encrypted locally before storage</small>
        </div>
        """, unsafe_allow_html=True)

def set_page_config():
    st.set_page_config(
        page_title="SecureVault",
        page_icon="🔒",
        layout="wide",
        initial_sidebar_state="expanded"
    )

if __name__ == "__main__":
    main()