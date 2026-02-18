import hashlib
import hmac
import os
from typing import Any

import google.generativeai as genai
import streamlit as st
from supabase import create_client

PROFILE_TABLE = "profiles"
AI_MODEL = "gemini-2.5-flash"


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


def build_error_text(exc: Exception) -> str:
    parts = [str(exc)]
    for attr in ("message", "details", "hint", "code"):
        value = getattr(exc, attr, None)
        if value is not None:
            parts.append(str(value))
    return " | ".join(parts).lower()


def map_db_error_message(error_text: str, fallback_message: str) -> str:
    if (
        "profiles_username_uidx" in error_text
        or "duplicate key value" in error_text
        or "23505" in error_text
    ):
        return "Username sudah dipakai. Gunakan username lain."
    if (
        "profiles_berat_nonneg" in error_text
        or "profiles_tinggi_nonneg" in error_text
        or "23514" in error_text
    ):
        return "Berat dan tinggi tidak boleh bernilai negatif."
    if "null value in column" in error_text or "not null" in error_text or "23502" in error_text:
        return "Data wajib tidak boleh kosong."
    return fallback_message


def get_supabase_client() -> Any:
    if "SUPABASE_URL" not in st.secrets or "SUPABASE_KEY" not in st.secrets:
        st.error("SUPABASE_URL dan SUPABASE_KEY belum diatur di secrets.")
        st.stop()

    try:
        return create_client(st.secrets["SUPABASE_URL"], st.secrets["SUPABASE_KEY"])
    except Exception:
        st.error("Gagal terhubung ke Supabase. Cek URL dan KEY di secrets.")
        st.stop()


def ensure_session() -> None:
    if "user" not in st.session_state:
        st.session_state.user = None


def register_user(supabase: Any, username: str, password: str) -> None:
    if not username or not password:
        st.warning("Username dan password wajib diisi.")
        return

    try:
        existing_user = (
            supabase.table(PROFILE_TABLE)
            .select("username")
            .eq("username", username)
            .limit(1)
            .execute()
        )
    except Exception as exc:
        error_text = build_error_text(exc)
        st.error(map_db_error_message(error_text, "Gagal cek username di database."))
        return

    if existing_user.data:
        st.warning("Username sudah dipakai. Gunakan username lain.")
        return

    try:
        data = {
            "username": username,
            "password": hash_password(password),
            "berat": 0,
            "tinggi": 0,
        }
        supabase.table(PROFILE_TABLE).insert(data).execute()
        st.success("Akun berhasil dibuat. Silakan login.")
    except Exception as exc:
        error_text = build_error_text(exc)
        st.error(map_db_error_message(error_text, "Gagal membuat akun. Coba lagi beberapa saat."))


def upgrade_legacy_password(supabase: Any, username: str, raw_password: str) -> str | None:
    try:
        new_hash = hash_password(raw_password)
        (
            supabase.table(PROFILE_TABLE)
            .update({"password": new_hash})
            .eq("username", username)
            .execute()
        )
        return new_hash
    except Exception:
        return None


def login_user(supabase: Any, username: str, password: str) -> None:
    if not username or not password:
        st.warning("Username dan password wajib diisi.")
        return

    try:
        res = (
            supabase.table(PROFILE_TABLE)
            .select("*")
            .eq("username", username)
            .limit(1)
            .execute()
        )
    except Exception as exc:
        error_text = build_error_text(exc)
        st.error(map_db_error_message(error_text, "Gagal mengakses database saat login."))
        return

    if not res.data:
        st.error("Username atau password salah.")
        return

    user_row = res.data[0]
    stored_password = str(user_row.get("password", ""))
    if not verify_password(password, stored_password):
        st.error("Username atau password salah.")
        return

    if not stored_password.startswith("pbkdf2_sha256$"):
        new_hash = upgrade_legacy_password(supabase, username, password)
        if new_hash:
            user_row["password"] = new_hash

    st.session_state.user = user_row
    st.rerun()


def render_auth_view(supabase: Any) -> None:
    menu = st.sidebar.selectbox("Menu", ["Login", "Daftar Akun"])
    username = st.text_input("Username").strip()
    password = st.text_input("Password", type="password")

    if menu == "Daftar Akun":
        if st.button("Buat Akun"):
            register_user(supabase, username, password)
    else:
        if st.button("Masuk"):
            login_user(supabase, username, password)


def update_profile_bmi(supabase: Any, username: str, berat: float, tinggi: float) -> bool:
    try:
        (
            supabase.table(PROFILE_TABLE)
            .update({"berat": berat, "tinggi": tinggi})
            .eq("username", username)
            .execute()
        )
        return True
    except Exception as exc:
        error_text = build_error_text(exc)
        st.error(map_db_error_message(error_text, "Data gagal disimpan ke database."))
        return False


def render_bmi_section(supabase: Any, user_data: dict[str, Any]) -> tuple[float, float]:
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
            if update_profile_bmi(supabase, user_data["username"], berat, tinggi):
                st.session_state.user["berat"] = berat
                st.session_state.user["tinggi"] = tinggi
                st.success(f"Data tersimpan. BMI Anda: {bmi:.2f} ({kategori_bmi(bmi)})")

    return berat, tinggi


def build_ai_prompt(berat: float, tinggi: float, pertanyaan: str) -> str:
    if berat > 0 and tinggi > 0:
        konteks_badan = f"Saya memiliki berat badan {berat:.1f} kg dan tinggi {tinggi:.1f} cm."
    else:
        konteks_badan = "Saya belum mengisi data berat dan tinggi, jadi berikan saran umum."
    return f"{konteks_badan} {pertanyaan}"


def render_ai_section(berat: float, tinggi: float) -> None:
    st.divider()
    st.subheader("Konsultasi dengan AI Diet Coach")
    pertanyaan = st.text_input("Tanya apa saja (contoh: menu makan malam sehat untuk saya?)")

    if "GOOGLE_API_KEY" not in st.secrets or not st.secrets["GOOGLE_API_KEY"]:
        st.info("Fitur AI belum aktif. Tambahkan GOOGLE_API_KEY di secrets.")
        return

    if not st.button("Tanya Coach"):
        return

    if not pertanyaan.strip():
        st.warning("Tuliskan pertanyaanmu dulu.")
        return

    prompt = build_ai_prompt(berat, tinggi, pertanyaan)
    with st.spinner("Coach sedang berpikir..."):
        try:
            genai.configure(api_key=st.secrets["GOOGLE_API_KEY"])
            model = genai.GenerativeModel(AI_MODEL)
            response = model.generate_content(prompt)
        except Exception:
            st.error("AI Coach gagal merespons. Cek API key atau koneksi.")
            return

    jawaban = getattr(response, "text", "")
    if jawaban:
        st.write(jawaban)
    else:
        st.warning("Coach belum memberi jawaban. Coba pertanyaan lain.")


def render_dashboard(supabase: Any) -> None:
    user_data = st.session_state.user
    st.sidebar.write(f"Login sebagai: **{user_data['username']}**")

    if st.sidebar.button("Logout"):
        st.session_state.user = None
        st.rerun()

    berat, tinggi = render_bmi_section(supabase, user_data)
    render_ai_section(berat, tinggi)


def main() -> None:
    st.title("Aplikasi Kesehatan Surya & Wisma")
    ensure_session()
    supabase = get_supabase_client()

    if st.session_state.user is None:
        render_auth_view(supabase)
    else:
        render_dashboard(supabase)


if __name__ == "__main__":
    main()
