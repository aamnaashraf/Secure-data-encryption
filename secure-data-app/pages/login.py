import streamlit as st
import hashlib
import os

st.set_page_config(initial_sidebar_state="collapsed")

def check_master_password():
    with st.form("master_auth"):
        password = st.text_input("Master Password", type="password")
        if st.form_submit_button("Authenticate"):
            hashed = hashlib.sha256(password.encode()).hexdigest()
            if hashed == os.environ.get("MASTER_PASS_HASH"):
                st.session_state.authenticated = True
                st.switch_page("main.py")
            else:
                st.error("Invalid master password")

st.title("🔒 Administrator Authentication")
check_master_password()