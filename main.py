import streamlit as st
import sqlite3
import bcrypt

# ---------------- Database Functions ---------------- #
def create_user_table():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('CREATE TABLE IF NOT EXISTS users(username TEXT, password TEXT)')
    conn.commit()
    conn.close()

def add_user(username, password):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('INSERT INTO users(username, password) VALUES (?, ?)', (username, password))
    conn.commit()
    conn.close()

def get_user(username):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE username=?', (username,))
    data = c.fetchone()
    conn.close()
    return data

# ---------------- Session Control ---------------- #
def show_login_page():
    st.subheader("Login to your account")
    username = st.text_input("Username")
    password = st.text_input("Password", type='password')

    if st.button("Login"):
        user = get_user(username)
        if user and bcrypt.checkpw(password.encode(), user[1]):
            st.session_state['logged_in'] = True
            st.session_state['username'] = username
            st.success(f"Welcome {username}!")
        else:
            st.error("Invalid username or password.")

def show_signup_page():
    st.subheader("Create Account")
    new_user = st.text_input("Username")
    new_password = st.text_input("Password", type='password')

    if st.button("Sign Up"):
        hashed_pw = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt())
        add_user(new_user, hashed_pw)
        st.success("Account created successfully! Go to Login.")

def show_protected_page():
    st.title("Protected Page")
    st.write(f"Welcome, {st.session_state['username']}! This is a secure page.")

# ---------------- Streamlit UI ---------------- #
st.title("Login System with SQLite")

# Create the user table if it doesn't exist
create_user_table()

# Check if the user is already logged in
if 'logged_in' not in st.session_state or not st.session_state['logged_in']:
    # Show the Welcome/Intro page or Login/Signup page
    menu = st.sidebar.selectbox("Menu", ["Home", "Login", "Sign Up"])

    if menu == "Home":
        st.write("Welcome to the website!")
        st.write("Please login or sign up to continue.")
    elif menu == "Login":
        show_login_page()
    elif menu == "Sign Up":
        show_signup_page()
else:
    # After login, show protected content
    show_protected_page()
