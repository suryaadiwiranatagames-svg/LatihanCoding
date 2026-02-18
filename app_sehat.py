import hashlib
import hmac
import os
from datetime import date
from typing import Any

import google.generativeai as genai
import streamlit as st
from supabase import create_client

PROFILE_TABLE = "profiles"
AI_MODEL = "gemini-2.5-flash"
AUTH_MENU_KEY = "auth_menu"
AUTH_MENU_TARGET_KEY = "auth_menu_target"
AUTH_RESET_PENDING_KEY = "auth_reset_pending"
LOGIN_USERNAME_KEY = "login_username"
LOGIN_PASSWORD_KEY = "login_password"
REG_NAMA_KEY = "reg_nama"
REG_USERNAME_KEY = "reg_username"
REG_PASSWORD_KEY = "reg_password"
REG_CONFIRM_PASSWORD_KEY = "reg_confirm_password"
REG_TEMPAT_LAHIR_KEY = "reg_tempat_lahir"
REG_TANGGAL_LAHIR_KEY = "reg_tanggal_lahir"
REG_NO_HP_KEY = "reg_no_hp"
REG_DOMISILI_KEY = "reg_domisili"


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
    if ("column" in error_text and "does not exist" in error_text) or "42703" in error_text:
        return "Kolom profil baru belum ada di database. Jalankan SQL migration dulu."
    return fallback_message


def is_valid_phone_number(no_hp: str) -> bool:
    normalized = no_hp.replace(" ", "").replace("-", "")
    if normalized.startswith("+"):
        normalized = normalized[1:]
    return normalized.isdigit() and 9 <= len(normalized) <= 15


def validate_registration_input(
    nama: str,
    username: str,
    password: str,
    confirm_password: str,
    tempat_lahir: str,
    no_hp: str,
    domisili: str,
) -> str | None:
    if not all([nama, username, password, confirm_password, tempat_lahir, no_hp, domisili]):
        return "Semua data pendaftaran wajib diisi."
    if password != confirm_password:
        return "Password dan konfirmasi password harus sama."
    if len(password) < 8:
        return "Password minimal 8 karakter."
    if not is_valid_phone_number(no_hp):
        return "No HP tidak valid. Gunakan angka saja (boleh diawali +)."
    return None


def ensure_auth_form_state() -> None:
    defaults: dict[str, Any] = {
        AUTH_MENU_KEY: "Login",
        AUTH_MENU_TARGET_KEY: None,
        AUTH_RESET_PENDING_KEY: False,
        LOGIN_USERNAME_KEY: "",
        LOGIN_PASSWORD_KEY: "",
        REG_NAMA_KEY: "",
        REG_USERNAME_KEY: "",
        REG_PASSWORD_KEY: "",
        REG_CONFIRM_PASSWORD_KEY: "",
        REG_TEMPAT_LAHIR_KEY: "",
        REG_TANGGAL_LAHIR_KEY: date.today(),
        REG_NO_HP_KEY: "",
        REG_DOMISILI_KEY: "",
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def clear_auth_form_state() -> None:
    st.session_state[LOGIN_USERNAME_KEY] = ""
    st.session_state[LOGIN_PASSWORD_KEY] = ""
    st.session_state[REG_NAMA_KEY] = ""
    st.session_state[REG_USERNAME_KEY] = ""
    st.session_state[REG_PASSWORD_KEY] = ""
    st.session_state[REG_CONFIRM_PASSWORD_KEY] = ""
    st.session_state[REG_TEMPAT_LAHIR_KEY] = ""
    st.session_state[REG_TANGGAL_LAHIR_KEY] = date.today()
    st.session_state[REG_NO_HP_KEY] = ""
    st.session_state[REG_DOMISILI_KEY] = ""


def apply_pending_auth_state_actions() -> None:
    target_menu = st.session_state.get(AUTH_MENU_TARGET_KEY)
    if target_menu in ("Login", "Daftar Akun"):
        st.session_state[AUTH_MENU_KEY] = target_menu
        st.session_state[AUTH_MENU_TARGET_KEY] = None

    if st.session_state.get(AUTH_RESET_PENDING_KEY):
        clear_auth_form_state()
        st.session_state[AUTH_RESET_PENDING_KEY] = False


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


def register_user(
    supabase: Any,
    nama: str,
    username: str,
    password: str,
    confirm_password: str,
    tempat_lahir: str,
    tanggal_lahir: date,
    no_hp: str,
    domisili: str,
) -> bool:
    validation_error = validate_registration_input(
        nama=nama,
        username=username,
        password=password,
        confirm_password=confirm_password,
        tempat_lahir=tempat_lahir,
        no_hp=no_hp,
        domisili=domisili,
    )
    if validation_error:
        st.warning(validation_error)
        return False

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
        return False

    if existing_user.data:
        st.warning("Username sudah dipakai. Gunakan username lain.")
        return False

    try:
        data = {
            "nama": nama,
            "username": username,
            "password": hash_password(password),
            "tempat_lahir": tempat_lahir,
            "tanggal_lahir": tanggal_lahir.isoformat(),
            "no_hp": no_hp,
            "domisili": domisili,
            "berat": 0,
            "tinggi": 0,
        }
        supabase.table(PROFILE_TABLE).insert(data).execute()
        st.success("Akun berhasil dibuat. Silakan login.")
        return True
    except Exception as exc:
        error_text = build_error_text(exc)
        st.error(map_db_error_message(error_text, "Gagal membuat akun. Coba lagi beberapa saat."))
        return False


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


def login_user(supabase: Any, username: str, password: str) -> bool:
    if not username or not password:
        st.warning("Username dan password wajib diisi.")
        return False

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
        return False

    if not res.data:
        st.error("Username atau password salah.")
        return False

    user_row = res.data[0]
    stored_password = str(user_row.get("password", ""))
    if not verify_password(password, stored_password):
        st.error("Username atau password salah.")
        return False

    if not stored_password.startswith("pbkdf2_sha256$"):
        new_hash = upgrade_legacy_password(supabase, username, password)
        if new_hash:
            user_row["password"] = new_hash

    st.session_state.user = user_row
    return True


def render_auth_view(supabase: Any) -> None:
    ensure_auth_form_state()
    apply_pending_auth_state_actions()
    menu = st.sidebar.selectbox("Menu", ["Login", "Daftar Akun"], key=AUTH_MENU_KEY)

    if menu == "Daftar Akun":
        nama = st.text_input("Nama lengkap", key=REG_NAMA_KEY).strip()
        username = st.text_input("Username akun", key=REG_USERNAME_KEY).strip()
        password = st.text_input("Password", type="password", key=REG_PASSWORD_KEY)
        confirm_password = st.text_input(
            "Konfirmasi password", type="password", key=REG_CONFIRM_PASSWORD_KEY
        )
        tempat_lahir = st.text_input("Tempat lahir", key=REG_TEMPAT_LAHIR_KEY).strip()
        tanggal_lahir = st.date_input(
            "Tanggal lahir", key=REG_TANGGAL_LAHIR_KEY, min_value=date(1900, 1, 1), max_value=date.today()
        )
        no_hp = st.text_input("No HP", key=REG_NO_HP_KEY).strip()
        domisili = st.text_input("Domisili", key=REG_DOMISILI_KEY).strip()

        if st.button("Buat Akun"):
            is_success = register_user(
                supabase=supabase,
                nama=nama,
                username=username,
                password=password,
                confirm_password=confirm_password,
                tempat_lahir=tempat_lahir,
                tanggal_lahir=tanggal_lahir,
                no_hp=no_hp,
                domisili=domisili,
            )
            if is_success:
                st.session_state[AUTH_RESET_PENDING_KEY] = True
                st.session_state[AUTH_MENU_TARGET_KEY] = "Login"
                st.rerun()
    else:
        username = st.text_input("Username", key=LOGIN_USERNAME_KEY).strip()
        password = st.text_input("Password", type="password", key=LOGIN_PASSWORD_KEY)
        if st.button("Masuk"):
            is_success = login_user(supabase, username, password)
            if is_success:
                st.session_state[AUTH_RESET_PENDING_KEY] = True
                st.rerun()


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
