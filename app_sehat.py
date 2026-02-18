import streamlit as st

# Tampilan Judul
st.title("Aplikasi Kesehatan Surya 🥗")
st.write("Pantau BMI dan progres kesehatanmu di sini.")

# Input Data
nama = st.text_input("Nama kamu:")
berat = st.number_input("Berat Badan (kg):", min_value=1.0)
tinggi_cm = st.number_input("Tinggi Badan (cm):", min_value=1.0)

if st.button("Hitung BMI"):
    # Logika Matematika
    tinggi_m = tinggi_cm / 100
    bmi = berat / (tinggi_m ** 2)
    
    st.subheader(f"Halo {nama}, BMI kamu adalah: {bmi:.2f}")
    
    # Kategori BMI (Berdasarkan logika kesehatan)
    if bmi < 18.5:
        st.warning("Kategori: Kekurangan Berat Badan")
    elif 18.5 <= bmi < 25:
        st.success("Kategori: Berat Badan Normal (Ideal)")
    else:
        st.error("Kategori: Kelebihan Berat Badan")