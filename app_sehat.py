import streamlit as st
from supabase import create_client
import google.generativeai as genai


# 1. Konek ke Supabase menggunakan rahasia kita
url = st.secrets["SUPABASE_URL"]
key = st.secrets["SUPABASE_KEY"]
supabase = create_client(url, key)

st.title("Aplikasi Kesehatan Surya & Wisma 🍎")

# 2. Logika "Ingatan" (Session State)
if "user" not in st.session_state:
    st.session_state.user = None

if st.session_state.user is None:
    menu = st.sidebar.selectbox("Menu", ["Login", "Daftar Akun"])
    
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if menu == "Daftar Akun":
        if st.button("Buat Akun"):
            # Masukkan ke tabel profiles di Supabase
            data = {"username": username, "password": password, "berat": 0, "tinggi": 0}
            supabase.table("profiles").insert(data).execute()
            st.success("Akun berhasil dibuat! Silakan pindah ke menu Login.")
            
    else:
        if st.button("Masuk"):
            # Cek di database
            res = supabase.table("profiles").select("*").eq("username", username).eq("password", password).execute()
            if len(res.data) > 0:
                st.session_state.user = res.data[0]
                st.rerun()
            else:
                st.error("Username atau Password salah!")

else:
    # --- HALAMAN UTAMA (Sudah Login) ---
    user_data = st.session_state.user
    st.sidebar.write(f"Logged in as: **{user_data['username']}**")
    
    if st.sidebar.button("Logout"):
        st.session_state.user = None
        st.rerun()

    berat = st.number_input("Berat Badan (kg):", value=float(user_data['berat']))
    tinggi = st.number_input("Tinggi Badan (cm):", value=float(user_data['tinggi']))

    if st.button("Simpan & Hitung BMI"):
        bmi = berat / ((tinggi/100) ** 2)
        # Update ke Supabase agar tersimpan permanen
        supabase.table("profiles").update({"berat": berat, "tinggi": tinggi}).eq("username", user_data['username']).execute()
        st.success(f"Data tersimpan! BMI Anda: {bmi:.2f}")


# Konfigurasi AI
genai.configure(api_key=st.secrets["GOOGLE_API_KEY"])
model = genai.GenerativeModel('gemini-2.5-flash')
st.divider()
st.subheader("💬 Konsultasi dengan AI Diet Coach")

# Input pertanyaan dari user
pertanyaan = st.text_input("Tanya apa saja (contoh: menu makan malam sehat untuk saya?)")

if st.button("Tanya Coach"):
    if pertanyaan:
        with st.spinner("Coach sedang berpikir..."):
            # Kita beri konteks ke AI agar jawabannya lebih akurat
            prompt = f"Saya memiliki berat badan {berat} kg dan tinggi {tinggi} cm. {pertanyaan}"
            response = model.generate_content(prompt)
            st.write(response.text)
    else:
        st.warning("Tuliskan pertanyaanmu dulu, Surya!")