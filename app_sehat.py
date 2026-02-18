import hashlib
import hmac
import os

import google.generativeai as genai
import streamlit as st
from supabase import create_client


def hash_password(password: str, iterations: int = 200_000) -> str:
    salt = os.urandom(16).hex()
    hashed = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), iterations)
    return f"pbkdf2_sha256${iterations}${salt}${hashed.hex()}"


def verify_password(password: str, stored_password: str) -> bool:
    if not stored_password:
        return False

    if stored_password.startswith("pbkdf2_sha256$"):
        try:
            _, iteration_str, salt, stored_hash = stored_password.split("$", 3)
            iterations = int(iteration_str)
            check_hash = hashlib.pbkdf2_hmac(
                "sha256", password.encode(), salt.encode(), iterations
            ).hex()
            return hmac.compare_digest(check_hash, stored_hash)
        except (ValueError, TypeError):
            return False

    # Fallback untuk akun lama yang masih plaintext.
    return hmac.compare_digest(password, stored_password)


def kategori_bmi(bmi: float) -> str:
    if bmi < 18.5:
        return "Kurus"
    if bmi < 25:
        return "Normal"
    if bmi < 30:
        return "Berat badan berlebih"
    return "Obesitas"


# 1. Konek ke Supabase menggunakan rahasia aplikasi
if "SUPABASE_URL" not in st.secrets or "SUPABASE_KEY" not in st.secrets:
    st.error("SUPABASE_URL dan SUPABASE_KEY belum diatur di secrets.")
    st.stop()

try:
    supabase = create_client(st.secrets["SUPABASE_URL"], st.secrets["SUPABASE_KEY"])
except Exception:
    st.error("Gagal terhubung ke Supabase. Cek URL dan KEY di secrets.")
    st.stop()

st.title("Aplikasi Kesehatan Surya & Wisma")

# 2. Session state untuk status login
if "user" not in st.session_state:
    st.session_state.user = None

if st.session_state.user is None:
    menu = st.sidebar.selectbox("Menu", ["Login", "Daftar Akun"])
    username = st.text_input("Username").strip()
    password = st.text_input("Password", type="password")

    if menu == "Daftar Akun":
        if st.button("Buat Akun"):
            if not username or not password:
                st.warning("Username dan password wajib diisi.")
            else:
                try:
                    existing_user = (
                        supabase.table("profiles")
                        .select("username")
                        .eq("username", username)
                        .limit(1)
                        .execute()
                    )
                    if existing_user.data:
                        st.warning("Username sudah dipakai. Gunakan username lain.")
                    else:
                        data = {
                            "username": username,
                            "password": hash_password(password),
                            "berat": 0,
                            "tinggi": 0,
                        }
                        supabase.table("profiles").insert(data).execute()
                        st.success("Akun berhasil dibuat. Silakan login.")
                except Exception:
                    st.error("Gagal membuat akun. Coba lagi beberapa saat.")

    else:
        if st.button("Masuk"):
            if not username or not password:
                st.warning("Username dan password wajib diisi.")
            else:
                try:
                    res = (
                        supabase.table("profiles")
                        .select("*")
                        .eq("username", username)
                        .limit(1)
                        .execute()
                    )
                except Exception:
                    st.error("Gagal mengakses database saat login.")
                else:
                    if not res.data:
                        st.error("Username atau password salah.")
                    else:
                        user_row = res.data[0]
                        if verify_password(password, user_row.get("password", "")):
                            # Upgrade otomatis jika password lama masih plaintext.
                            if not str(user_row.get("password", "")).startswith(
                                "pbkdf2_sha256$"
                            ):
                                try:
                                    new_hash = hash_password(password)
                                    (
                                        supabase.table("profiles")
                                        .update({"password": new_hash})
                                        .eq("username", username)
                                        .execute()
                                    )
                                    user_row["password"] = new_hash
                                except Exception:
                                    pass

                            st.session_state.user = user_row
                            st.rerun()
                        else:
                            st.error("Username atau password salah.")

else:
    # 3. Halaman utama setelah login
    user_data = st.session_state.user
    st.sidebar.write(f"Login sebagai: **{user_data['username']}**")

    if st.sidebar.button("Logout"):
        st.session_state.user = None
        st.rerun()

    berat_awal = float(user_data.get("berat") or 0)
    tinggi_awal = float(user_data.get("tinggi") or 0)

    berat = st.number_input(
        "Berat badan (kg):", min_value=0.0, value=berat_awal, step=0.1
    )
    tinggi = st.number_input(
        "Tinggi badan (cm):", min_value=0.0, value=tinggi_awal, step=0.1
    )

    if st.button("Simpan & Hitung BMI"):
        if berat <= 0:
            st.warning("Berat badan harus lebih dari 0 kg.")
        elif tinggi <= 0:
            st.warning("Tinggi badan harus lebih dari 0 cm.")
        else:
            bmi = berat / ((tinggi / 100) ** 2)
            try:
                (
                    supabase.table("profiles")
                    .update({"berat": berat, "tinggi": tinggi})
                    .eq("username", user_data["username"])
                    .execute()
                )
            except Exception:
                st.error("Data gagal disimpan ke database.")
            else:
                st.session_state.user["berat"] = berat
                st.session_state.user["tinggi"] = tinggi
                st.success(f"Data tersimpan. BMI Anda: {bmi:.2f} ({kategori_bmi(bmi)})")

    # 4. Konsultasi AI (hanya untuk user yang sudah login)
    st.divider()
    st.subheader("Konsultasi dengan AI Diet Coach")
    pertanyaan = st.text_input(
        "Tanya apa saja (contoh: menu makan malam sehat untuk saya?)"
    )

    if "GOOGLE_API_KEY" not in st.secrets or not st.secrets["GOOGLE_API_KEY"]:
        st.info("Fitur AI belum aktif. Tambahkan GOOGLE_API_KEY di secrets.")
    elif st.button("Tanya Coach"):
        if not pertanyaan.strip():
            st.warning("Tuliskan pertanyaanmu dulu.")
        else:
            if berat > 0 and tinggi > 0:
                konteks_badan = (
                    f"Saya memiliki berat badan {berat:.1f} kg dan tinggi {tinggi:.1f} cm."
                )
            else:
                konteks_badan = (
                    "Saya belum mengisi data berat dan tinggi, jadi berikan saran umum."
                )

            prompt = f"{konteks_badan} {pertanyaan}"
            with st.spinner("Coach sedang berpikir..."):
                try:
                    genai.configure(api_key=st.secrets["GOOGLE_API_KEY"])
                    model = genai.GenerativeModel("gemini-2.5-flash")
                    response = model.generate_content(prompt)
                except Exception:
                    st.error("AI Coach gagal merespons. Cek API key atau koneksi.")
                else:
                    jawaban = getattr(response, "text", "")
                    if jawaban:
                        st.write(jawaban)
                    else:
                        st.warning("Coach belum memberi jawaban. Coba pertanyaan lain.")
