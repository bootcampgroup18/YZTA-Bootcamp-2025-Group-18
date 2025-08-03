
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
import json
import os
from dotenv import load_dotenv
import hashlib
import sqlite3
from pathlib import Path
import google.generativeai as genai

# Load environment variables
load_dotenv()

# Page configuration
st.set_page_config(
    page_title="Doktor-Hasta İletişim Sistemi",
    page_icon="🏥",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 3rem;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 2rem;
    }
    .sub-header {
        font-size: 1.5rem;
        color: #2c3e50;
        margin-bottom: 1rem;
    }
    .info-box {
        background-color: #f8f9fa;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #1f77b4;
        margin: 1rem 0;
        color: #2c3e50;
    }
    .success-box {
        background-color: #d4edda;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #28a745;
        margin: 1rem 0;
        color: #2c3e50;
    }
    .warning-box {
        background-color: #fff3cd;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #ffc107;
        margin: 1rem 0;
        color: #2c3e50;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'current_user' not in st.session_state:
    st.session_state.current_user = None
if 'user_type' not in st.session_state:
    st.session_state.user_type = None
if 'conversations' not in st.session_state:
    st.session_state.conversations = {}


def init_database():
    """Initialize SQLite database"""
    conn = sqlite3.connect('doctor_patient_system.db')
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            user_type TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS conversations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id INTEGER,
            doctor_id INTEGER,
            message TEXT NOT NULL,
            sender_type TEXT NOT NULL,
            ai_analysis TEXT,
            ai_doctor_analysis TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (patient_id) REFERENCES users (id),
            FOREIGN KEY (doctor_id) REFERENCES users (id)
        )
    ''')
    conn.commit()
    conn.close()


def hash_password(password):
    """Hash password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()


def register_user(username, password, user_type):
    """Kayıt Ol a new user"""
    conn = sqlite3.connect('doctor_patient_system.db')
    cursor = conn.cursor()

    try:
        password_hash = hash_password(password)
        cursor.execute(
            'INSERT INTO users (username, password_hash, user_type) VALUES (?, ?, ?)',
            (username, password_hash, user_type)
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()


def authenticate_user(username, password):
    """Authenticate user login"""
    conn = sqlite3.connect('doctor_patient_system.db')
    cursor = conn.cursor()

    password_hash = hash_password(password)
    cursor.execute(
        'SELECT id, username, user_type FROM users WHERE username = ? AND password_hash = ?',
        (username, password_hash)
    )
    user = cursor.fetchone()
    conn.close()

    return user


def save_message(patient_id, doctor_id, message, sender_type, ai_analysis=None, ai_doctor_analysis=None):
    """Save message to database"""
    conn = sqlite3.connect('doctor_patient_system.db')
    cursor = conn.cursor()

    cursor.execute(
        'INSERT INTO conversations (patient_id, doctor_id, message, sender_type, ai_analysis, ai_doctor_analysis) VALUES (?, ?, ?, ?, ?, ?)',
        (patient_id, doctor_id, message, sender_type, ai_analysis, ai_doctor_analysis)
    )
    conn.commit()
    conn.close()


# DEĞİŞİKLİK: get_conversation_history fonksiyonu daha esnek hale getirildi
def get_conversation_history(patient_id):
    """Get all conversations for a specific patient."""
    conn = sqlite3.connect('doctor_patient_system.db')
    cursor = conn.cursor()

    cursor.execute('''
        SELECT message, sender_type, ai_analysis, timestamp, ai_doctor_analysis
        FROM conversations
        WHERE patient_id = ?
        ORDER BY timestamp
    ''', (patient_id,))

    messages = cursor.fetchall()
    conn.close()
    return messages


def get_patient_complaint_history(patient_id):
    """Fetches all past complaints submitted by a specific patient."""
    conn = sqlite3.connect('doctor_patient_system.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT timestamp, message, ai_analysis
        FROM conversations
        WHERE patient_id = ? AND sender_type = 'patient'
        ORDER BY timestamp DESC
    ''', (patient_id,))
    history = cursor.fetchall()
    conn.close()
    return history


# Gemini AI function
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
model = genai.GenerativeModel("gemini-1.5-flash-latest")


def get_patient_ai_suggestion(symptoms_text):
    """Generates simple, reassuring advice for the patient."""
    prompt = f"""Bir hastaya, aşağıdaki belirtileri için basit, sakinleştirici ve genel sağlık önerileri ver. Tıbbi tanı koymaktan kaçın. Sadece genel tavsiyelerde bulun (örneğin 'dinlenin', 'bol sıvı tüketin', 'belirtiler kötüleşirse doktora başvurun' gibi).
    Belirtiler: {symptoms_text}
    Yanıt dili Türkçe ve çok basit olmalı."""
    try:
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        return f"Yapay zekâ analiz hatası: {str(e)}"


def get_doctor_ai_analysis(symptoms_text):
    """Generates a technical pre-assessment for a doctor."""
    prompt = f"""Sen uzman bir hekimsin. Bir meslektaşına (başka bir doktora) aşağıdaki belirtilerle ilgili bir ön değerlendirme sunuyorsun. Olası tanılar, ayırıcı tanılar, önerilebilecek testler ve potansiyel tedavi başlangıçları hakkında tıbbi terminoloji kullanarak bir analiz yap.
    Belirtiler: {symptoms_text}
    Yanıt dili Türkçe olmalı ve bir hekime yönelik profesyonel bir üslup kullanmalı."""
    try:
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        return f"Yapay zekâ analiz hatası: {str(e)}"


# Authentication page
def show_auth_page():
    st.markdown('<h1 class="main-header">🏥 Doktor-Hasta İletişim Sistemi</h1>', unsafe_allow_html=True)

    tab1, tab2 = st.tabs(["Giriş Yap", "Kayıt Ol"])

    with tab1:
        st.markdown('<h2 class="sub-header">Giriş Yap</h2>', unsafe_allow_html=True)

        with st.form("login_form"):
            username = st.text_input("Kullanıcı Adı")
            password = st.text_input("Şifre", type="password")
            user_type_selection = st.selectbox("Kullanıcı Türü",
                                               ["Hasta", "Doktor"])
            submit_button = st.form_submit_button("Giriş Yap")

            if submit_button:
                if username and password:
                    user = authenticate_user(username, password)
                    if user:
                        if user[2] == user_type_selection:
                            st.session_state.current_user = {
                                'id': user[0],
                                'username': user[1],
                                'user_type': user[2].lower()
                            }
                            st.session_state.user_type = user[2].lower()
                            st.success("Giriş başarılı!")
                            st.rerun()
                        else:
                            st.error("Kullanıcı türü yanlış. Lütfen doğru türü seçin.")
                    else:
                        st.error("Geçersiz kullanıcı adı veya şifre")
                else:
                    st.error("Lütfen tüm alanları doldurun")

    with tab2:
        st.markdown('<h2 class="sub-header">Kayıt Ol</h2>', unsafe_allow_html=True)

        with st.form("register_form"):
            new_username = st.text_input("Yeni Kullanıcı Adı")
            new_password = st.text_input("Yeni Şifre", type="password")
            confirm_password = st.text_input("Şifreyi Onayla", type="password")
            new_user_type = st.selectbox("Kullanıcı Türü", ["Hasta", "Doktor"], key="reg_user_type")
            register_button = st.form_submit_button("Kayıt Ol")

            if register_button:
                if new_username and new_password and confirm_password:
                    if new_password == confirm_password:
                        if register_user(new_username, new_password, new_user_type):
                            st.success("Kayıt başarılı! Lütfen giriş yapın.")
                        else:
                            st.error("Bu kullanıcı adı zaten mevcut")
                    else:
                        st.error("Şifreler eşleşmiyor")
                else:
                    st.error("Lütfen tüm alanları doldurun")


# Main dashboard
def show_dashboard():
    st.markdown('<h1 class="main-header">🏥 Doktor-Hasta İletişim Sistemi</h1>', unsafe_allow_html=True)

    with st.sidebar:
        st.markdown(f"**Hoşgeldiniz, {st.session_state.current_user['username']}**")
        st.markdown(f"**Kullanıcı Türü:** {st.session_state.current_user['user_type'].capitalize()}")

        if st.button("Çıkış Yap"):
            st.session_state.current_user = None
            st.session_state.user_type = None
            st.rerun()

        st.markdown("---")

        if st.session_state.user_type == "hasta":
            page = st.radio(
                "Navigasyon",
                ["Semptomları Yaz", "Doktor Cevapları", "Tıbbi Geçmiş"]
            )
        else:
            page = st.radio(
                "Navigasyon",
                ["Hasta Mesajları", "Hastaları Cevapla", "Hasta Analizi"]
            )

    if st.session_state.user_type == "hasta":
        if page == "Semptomları Yaz":
            show_patient_symptoms_page()
        elif page == "Doktor Cevapları":
            show_patient_responses_page()
        elif page == "Tıbbi Geçmiş":
            show_medical_history_page()
    else:
        if page == "Hasta Mesajları":
            show_doctor_messages_page()
        elif page == "Hastaları Cevapla":
            show_doctor_responses_page()
        elif page == "Hasta Analizi":
            show_analytics_page()


# Patient pages
def show_patient_symptoms_page():
    st.markdown('<h2 class="sub-header">📝 Belirtilerinizi Yazın</h2>', unsafe_allow_html=True)

    st.markdown("""
    <div class="info-box">
        <strong>Talimatlar:</strong><br>
        • Belirtilerinizi detaylı olarak açıklayın<br>
        • Süresini ve şiddetini belirtin<br>
        • Kullandığınız ilaçları ekleyin<br>
        • İlgili tıbbi geçmişinizi yazın
    </div>
    """, unsafe_allow_html=True)

    with st.form("symptoms_form"):
        symptoms = st.text_area(
            "Belirtilerinizi açıklayın:",
            height=200,
            placeholder="Lütfen belirtilerinizi detaylı bir şekilde yazın..."
        )
        urgency = st.selectbox(
            "Aciliyet Seviyesi:",
            ["Düşük", "Orta", "Yüksek", "Acil"]
        )
        submit_symptoms = st.form_submit_button("Belirtileri Gönder")

        if submit_symptoms and symptoms:
            with st.spinner("Analiz ediliyor ve kaydediliyor..."):
                patient_suggestion = get_patient_ai_suggestion(symptoms)
                doctor_analysis = get_doctor_ai_analysis(symptoms)

                # Not: doctor_id=1 geçici bir çözümdür. Gerçek sistemde dinamik olmalıdır.
                save_message(
                    patient_id=st.session_state.current_user['id'],
                    doctor_id=1,
                    message=symptoms,
                    sender_type="patient",
                    ai_analysis=patient_suggestion,
                    ai_doctor_analysis=doctor_analysis
                )

            st.success("Belirtileriniz başarıyla doktora iletildi!")
            with st.expander("🤖 Yapay Zeka Ön Değerlendirmesi", expanded=True):
                st.markdown(patient_suggestion)


def show_patient_responses_page():
    st.markdown('<h2 class="sub-header">👨‍⚕️ Doktor Cevapları</h2>', unsafe_allow_html=True)

    # DEĞİŞİKLİK: Mesajlaşma hatasını düzeltmek için sabit doktor ID'si kaldırıldı.
    messages = get_conversation_history(st.session_state.current_user['id'])

    if not messages:
        st.info("Henüz bir mesajınız yok. 'Belirtilerinizi Yazın' sayfasından ilk mesajınızı gönderebilirsiniz.")
        return

    for message in messages:
        message_text, sender_type, ai_analysis, timestamp, _ = message

        if sender_type == "doctor":
            st.markdown(f"""
            <div class="success-box">
                <strong>👨‍⚕️ Doktor Cevabı</strong><br>
                <small>{timestamp}</small><br><br>
                {message_text}
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown(f"""
            <div class="info-box">
                <strong>📝 Sizin Mesajınız</strong><br>
                <small>{timestamp}</small><br><br>
                {message_text}
            </div>
            """, unsafe_allow_html=True)
            if ai_analysis:
                with st.expander("🤖 Yapay Zeka Ön Değerlendirmesi", expanded=False):
                    st.write(ai_analysis)


# DEĞİŞİKLİK: Tıbbi Geçmiş sayfası dinamik tablo ve grafiğe dönüştürüldü
def show_medical_history_page():
    st.markdown('<h2 class="sub-header">📋 Tıbbi Geçmişiniz</h2>', unsafe_allow_html=True)

    patient_id = st.session_state.current_user['id']
    history = get_patient_complaint_history(patient_id)

    if not history:
        st.info(
            "Görüntülenecek bir tıbbi geçmişiniz bulunmamaktadır. 'Semptomları Yaz' sayfasından ilk kaydınızı oluşturabilirsiniz.")
        return

    # Veriyi DataFrame'e dönüştür
    history_df = pd.DataFrame(history, columns=['Tarih', 'Şikayetiniz', 'AI Ön Değerlendirmesi'])
    history_df['Tarih'] = pd.to_datetime(history_df['Tarih'])

    st.markdown("### Geçmiş Şikayetleriniz ve Analizler")
    st.dataframe(history_df, use_container_width=True)

    st.markdown("---")
    st.markdown("### Şikayet Zaman Çizelgesi")

    # Grafik için veriyi hazırla
    complaints_over_time = history_df.copy()
    complaints_over_time['Tarih'] = complaints_over_time['Tarih'].dt.to_period("D")
    complaints_per_day = complaints_over_time.groupby('Tarih').size().reset_index(name='count')
    complaints_per_day['Tarih'] = complaints_per_day['Tarih'].dt.to_timestamp()

    if not complaints_per_day.empty:
        fig = px.line(complaints_per_day, x='Tarih', y='count', title='Güne Göre Şikayet Sayısı', markers=True)
        fig.update_layout(xaxis_title='Tarih', yaxis_title='Şikayet Sayısı')
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("Grafik oluşturmak için yeterli veri yok.")


# Doctor pages
def show_doctor_messages_page():
    st.markdown('<h2 class="sub-header">📋 Hasta Mesajları</h2>', unsafe_allow_html=True)

    conn = sqlite3.connect('doctor_patient_system.db')
    cursor = conn.cursor()

    cursor.execute('''
        SELECT c.id, u.username, u.id as patient_id, c.message, c.ai_doctor_analysis, c.timestamp
        FROM conversations c
        JOIN users u ON c.patient_id = u.id
        WHERE c.sender_type = 'patient'
        ORDER BY c.timestamp DESC
    ''')
    messages = cursor.fetchall()
    conn.close()

    if not messages:
        st.info("Henüz hasta mesajı bulunmamaktadır.")
        return

    for msg_id, username, patient_id, message, ai_doctor_analysis, timestamp in messages:
        with st.expander(f"Hasta: {username} - {timestamp}", expanded=False):
            st.markdown(f"**Hasta Mesajı:**")
            st.write(message)

            if ai_doctor_analysis:
                st.markdown("**🤖 Yapay Zeka Tıbbi Değerlendirmesi:**")
                st.info(ai_doctor_analysis)

            with st.form(f"response_form_{msg_id}"):
                response = st.text_area("Cevabınız:", key=f"response_{msg_id}", height=150)
                submit_response = st.form_submit_button("Cevabı Gönder")

                if submit_response and response:
                    save_message(
                        patient_id=patient_id,
                        doctor_id=st.session_state.current_user['id'],
                        message=response,
                        sender_type="doctor"
                    )
                    st.success(f"{username} adlı hastaya cevap gönderildi!")
                    st.rerun()


def show_doctor_responses_page():
    st.markdown('<h2 class="sub-header">💬 Hastaları Cevapla</h2>', unsafe_allow_html=True)

    conn = sqlite3.connect('doctor_patient_system.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT DISTINCT u.id, u.username
        FROM conversations c
        JOIN users u ON c.patient_id = u.id
        WHERE c.sender_type = 'patient'
    ''')
    patients = cursor.fetchall()
    conn.close()

    if not patients:
        st.info("Mesaj gönderen hasta bulunmamaktadır.")
        return

    patient_options = {f"{p[1]} (ID: {p[0]})": p[0] for p in patients}
    selected_patient_display = st.selectbox("Hasta Seçin:", list(patient_options.keys()))

    if selected_patient_display:
        patient_id = patient_options[selected_patient_display]
        st.markdown("---")
        st.markdown(f"### {selected_patient_display} ile Konuşma Geçmişi")

        # DEĞİŞİKLİK: Mesajlaşma hatasını düzeltmek için sabit doktor ID'si kaldırıldı.
        messages = get_conversation_history(patient_id)

        for message in messages:
            message_text, sender_type, _, timestamp, ai_doctor_analysis = message

            if sender_type == "doctor":
                st.markdown(f"""
                <div class="success-box">
                    <strong>👨‍⚕️ Sizin Cevabınız</strong><br>
                    <small>{timestamp}</small><br><br>
                    {message_text}
                </div>
                """, unsafe_allow_html=True)
            else:
                st.markdown(f"""
                <div class="info-box">
                    <strong>📝 Hasta Mesajı</strong><br>
                    <small>{timestamp}</small><br><br>
                    {message_text}
                </div>
                """, unsafe_allow_html=True)
                if ai_doctor_analysis:
                    with st.expander("🤖 Yapay Zeka Tıbbi Değerlendirmesi", expanded=False):
                        st.info(ai_doctor_analysis)

        with st.form("doctor_response_form"):
            response = st.text_area("Cevabınızı yazın:")
            submit = st.form_submit_button("Cevabı Gönder")

            if submit and response:
                save_message(
                    patient_id=patient_id,
                    doctor_id=st.session_state.current_user['id'],
                    message=response,
                    sender_type="doctor"
                )
                st.success("Cevap gönderildi!")
                st.rerun()


def show_analytics_page():
    st.markdown('<h2 class="sub-header">📊 Hasta Analizi</h2>', unsafe_allow_html=True)

    conn = sqlite3.connect('doctor_patient_system.db')
    try:
        query = 'SELECT u.username, c.timestamp FROM conversations c JOIN users u ON c.patient_id = u.id'
        df = pd.read_sql_query(query, conn)
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df['date'] = df['timestamp'].dt.date
    except Exception as e:
        st.error(f"Analiz verileri yüklenemedi: {e}")
        return
    finally:
        conn.close()

    if df.empty:
        st.info("Analiz için yeterli veri bulunmamaktadır.")
        return

    total_patients = df['username'].nunique()
    total_messages = len(df)
    today = datetime.now().date()
    messages_today = len(df[df['date'] == today])

    col1, col2, col3 = st.columns(3)
    col1.metric("Toplam Hasta", f"{total_patients}")
    col2.metric("Toplam Mesaj", f"{total_messages}")
    col3.metric("Bugünkü Mesajlar", f"{messages_today}")

    st.markdown("---")

    messages_per_day = df.groupby(df['timestamp'].dt.to_period("D")).size().reset_index(name='count')
    messages_per_day['timestamp'] = messages_per_day['timestamp'].dt.to_timestamp()
    fig1 = px.line(messages_per_day, x='timestamp', y='count', title='Güne Göre Mesaj Sayısı', markers=True)
    fig1.update_layout(xaxis_title='Tarih', yaxis_title='Mesaj Sayısı')
    st.plotly_chart(fig1, use_container_width=True)

    messages_per_patient = df.groupby('username').size().reset_index(name='message_count')
    fig2 = px.bar(messages_per_patient, x='username', y='message_count', title='Hastaya Göre Mesaj Sayısı')
    fig2.update_layout(xaxis_title='Hasta Kullanıcı Adı', yaxis_title='Mesaj Sayısı')
    st.plotly_chart(fig2, use_container_width=True)


# Main app
def main():
    init_database()
    if st.session_state.current_user is None:
        show_auth_page()
    else:
        show_dashboard()


if __name__ == "__main__":
    main()