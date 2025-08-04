import streamlit as st
from crypto_utils import encrypt, decrypt
from user_utils import register_user, authenticate_user
import os

st.set_page_config(page_title="🔐 Secure Messaging")

MSG_DIR = "messages"
os.makedirs(MSG_DIR, exist_ok=True)

st.title("🔐 Secure Messaging App")

if "user" not in st.session_state:
    st.session_state.user = None

def login_ui():
    st.subheader("Login or Register")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if authenticate_user(username, password):
            st.session_state.user = username
            st.success(f"Welcome back, {username}!")
        else:
            st.error("Invalid credentials.")

    if st.button("Register"):
        if register_user(username, password):
            st.success("Registration successful! Please login.")
        else:
            st.warning("Username already exists.")

def secure_messaging_ui():
    st.sidebar.write(f"🔓 Logged in as: `{st.session_state.user}`")
    st.sidebar.button("Logout", on_click=lambda: st.session_state.update(user=None))

    tab1, tab2 = st.tabs(["📤 Send", "📥 Receive"])

    with tab1:
        st.subheader("Send Message or File")
        receiver = st.text_input("To (Username)")
        password = st.text_input("Encryption Password", type="password")
        message = st.text_area("Message")
        file = st.file_uploader("Or Upload File", type=None)

        if st.button("Encrypt & Send"):
            if not receiver:
                st.warning("Receiver username required.")
                return

            if message:
                data = message.encode()
                filename = f"{receiver}_{st.session_state.user}_msg.bin"
            elif file:
                data = file.read()
                filename = f"{receiver}_{st.session_state.user}_{file.name}.bin"
            else:
                st.warning("Provide a message or file.")
                return

            encrypted = encrypt(data, password)
            with open(os.path.join(MSG_DIR, filename), "wb") as f:
                f.write(encrypted)

            st.success("Encrypted & sent successfully!")

    with tab2:
        st.subheader("Decrypt Received Messages")
        password = st.text_input("Decryption Password", type="password")
        received_files = [f for f in os.listdir(MSG_DIR) if f.startswith(st.session_state.user)]

        if received_files:
            file_choice = st.selectbox("Choose a file", received_files)
            if st.button("Decrypt"):
                file_path = os.path.join(MSG_DIR, file_choice)
                with open(file_path, "rb") as f:
                    encrypted_data = f.read()

                try:
                    plain = decrypt(encrypted_data, password)  # ✅ Corrected
                    decoded = plain.decode()
                    st.text_area("Decrypted Message", decoded, height=150)
                except UnicodeDecodeError:
                    original_name = "_".join(file_choice.split("_")[2:]).replace(".bin", "")
                    st.download_button("Download File", plain, file_name=original_name)
                except Exception as e:
                    st.error(f"Decryption failed: {e}")
        else:
            st.info("No messages/files found.")

if st.session_state.user:
    secure_messaging_ui()
else:
    login_ui()
