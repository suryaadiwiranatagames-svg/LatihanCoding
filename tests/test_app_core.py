import unittest

from app_sehat import (
    build_ai_prompt,
    build_error_text,
    hash_password,
    kategori_bmi,
    map_db_error_message,
    verify_password,
)


class TestAppCore(unittest.TestCase):
    def test_hash_password_format_and_not_plaintext(self):
        raw = "rahasia123"
        hashed = hash_password(raw)

        self.assertTrue(hashed.startswith("pbkdf2_sha256$"))
        self.assertNotEqual(hashed, raw)

    def test_verify_password_for_hashed_password(self):
        raw = "rahasia123"
        hashed = hash_password(raw)

        self.assertTrue(verify_password(raw, hashed))
        self.assertFalse(verify_password("salah-password", hashed))

    def test_verify_password_for_legacy_plaintext(self):
        self.assertTrue(verify_password("abc123", "abc123"))
        self.assertFalse(verify_password("abc123", "xyz987"))

    def test_kategori_bmi_boundaries(self):
        self.assertEqual(kategori_bmi(17.0), "Kurus")
        self.assertEqual(kategori_bmi(18.5), "Normal")
        self.assertEqual(kategori_bmi(24.9), "Normal")
        self.assertEqual(kategori_bmi(25.0), "Berat badan berlebih")
        self.assertEqual(kategori_bmi(29.9), "Berat badan berlebih")
        self.assertEqual(kategori_bmi(30.0), "Obesitas")

    def test_build_ai_prompt_with_and_without_body_data(self):
        prompt_with_data = build_ai_prompt(70, 170, "Beri menu sehat")
        self.assertIn("70.0 kg", prompt_with_data)
        self.assertIn("170.0 cm", prompt_with_data)
        self.assertIn("Beri menu sehat", prompt_with_data)

        prompt_without_data = build_ai_prompt(0, 0, "Beri menu sehat")
        self.assertIn("belum mengisi data berat dan tinggi", prompt_without_data)

    def test_map_db_error_message_for_unique_violation(self):
        message = map_db_error_message(
            "duplicate key value violates unique constraint profiles_username_uidx",
            "fallback",
        )
        self.assertEqual(message, "Username sudah dipakai. Gunakan username lain.")

    def test_map_db_error_message_for_check_violation(self):
        message = map_db_error_message(
            "new row for relation profiles violates check constraint profiles_berat_nonneg",
            "fallback",
        )
        self.assertEqual(message, "Berat dan tinggi tidak boleh bernilai negatif.")

    def test_map_db_error_message_fallback(self):
        message = map_db_error_message("some unknown error", "pesan default")
        self.assertEqual(message, "pesan default")

    def test_build_error_text_from_exception_object(self):
        class DummyException(Exception):
            def __init__(self):
                self.message = "duplicate key"
                self.details = "profiles_username_uidx"
                self.hint = "username unique"
                self.code = "23505"

            def __str__(self):
                return "api error"

        text = build_error_text(DummyException())
        self.assertIn("api error", text)
        self.assertIn("profiles_username_uidx", text)
        self.assertIn("23505", text)


if __name__ == "__main__":
    unittest.main()
