import unittest

from app_sehat import build_ai_prompt, hash_password, kategori_bmi, verify_password


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


if __name__ == "__main__":
    unittest.main()
