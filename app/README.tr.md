# 🏥 Yapay Zekâ Destekli Doktor-Hasta İletişim Sistemi

Bu proje, doktor ve hasta arasındaki iletişimi kolaylaştırmak için geliştirilen gelişmiş bir **Streamlit tabanlı web uygulamasıdır**. Yapay zekâ destekli mesaj analiz sistemi, kullanıcı girişi ve hasta geçmişi özellikleriyle birlikte gelir.

---

## ⚙️ Özellikler

- 👥 Kullanıcı girişi (doktor & hasta)
- 💬 Gerçek zamanlı mesajlaşma arayüzü
- 🧠 Gemini AI ile mesaj analizi
- 📚 Mesaj geçmişi (konuşmalar) veritabanına kaydedilir
- 🔐 Güvenli şifreleme (hashlenmiş şifreler)
- 🌐 Etkileşimli ve şık Streamlit arayüzü

---

## 🚀 Kurulum

```bash
# 1. Depoyu klonlayın
$ git clone https://github.com/kullanici-adi/doctor-patient-system.git
$ cd doctor-patient-system/app2

# 2. Ortamı oluşturun (isteğe bağlı)
$ python3 -m venv venv
$ source venv/bin/activate  # Windows: venv\Scripts\activate

# 3. Bağımlılıkları kurun
$ pip install -r requirements.txt

# 4. Ortam değişkenlerini ayarlayın
$ cp .env.example .env  # Ardından Gemini API anahtarınızı ekleyin

# 5. Uygulamayı başlatın
$ streamlit run app.py
```

---

## ▶️ Kullanım

Uygulama başlatıldığında genellikle `http://localhost:8501` adresinde açılır.

### 👨‍⚕️ Doktorlar:
- Giriş yapabilir ya da kayıt olabilir
- Hastaları listeleyebilir ve onlarla mesajlaşabilir
- Gemini AI analizini görebilir, kendi yorumunu ekleyebilir

### 👤 Hastalar:
- Giriş yapabilir ya da kayıt olabilir
- Doktora mesaj atabilir
- AI analizini görüntüleyebilir

---

## 🧠 Yapay Zekâ Entegrasyonu

Google Gemini API kullanılarak:
- Hasta mesajları analiz edilir
- Olası tanı ve öneriler sunulur
- Doktorun değerlendirme süreci hızlandırılır

`.env` dosyasında aşağıdaki gibi bir anahtar gerekir:
```bash
GOOGLE_API_KEY=your_gemini_api_key_here
```

---

## 🗃️ Veritabanı Yapısı (SQLite)

### `users` tablosu
| Alan | Tip | Açıklama |
|------|-----|----------|
| id | INTEGER | Birincil anahtar |
| username | TEXT | Benzersiz kullanıcı adı |
| password_hash | TEXT | Hash'lenmiş şifre |
| user_type | TEXT | 'doctor' veya 'patient' |
| created_at | TIMESTAMP | Kayıt tarihi |

### `conversations` tablosu
| Alan | Tip | Açıklama |
|------|-----|----------|
| id | INTEGER | Birincil anahtar |
| patient_id | INTEGER | Kullanıcı id (hasta) |
| doctor_id | INTEGER | Kullanıcı id (doktor) |
| message | TEXT | Mesaj metni |
| sender_type | TEXT | 'doctor' veya 'patient' |
| ai_analysis | TEXT | Gemini AI analizi |
| ai_doctor_analysis | TEXT | Doktorun kendi yorumu |
| timestamp | TIMESTAMP | Mesaj zamanı |

---

## 📦 Gereksinimler

- Python 3.7+
- Streamlit
- sqlite3
- python-dotenv
- google-generativeai
- plotly

---

## 📄 Lisans

Bu proje MIT Lisansı ile lisanslanmıştır.

---

Her türlü katkı ve geri bildirim memnuniyetle karşılanır 🙌
