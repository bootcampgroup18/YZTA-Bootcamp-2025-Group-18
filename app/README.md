# 🏥 Doctor-Patient Communication System with AI Support

This is an advanced **Streamlit-based web application** for managing doctor-patient interactions. It includes AI-powered message analysis, user login system, and a conversation history for each patient. 

---

## ⚙️ Features

- 👥 User login (doctor & patient)
- 💬 Doctor-patient messaging interface
- 🧠 Gemini AI-powered message analysis
- 📚 Conversation history stored in SQLite
- 🔐 Secure user authentication with hashed passwords
- 🌐 Responsive and interactive Streamlit UI

---

## 🚀 Installation

```bash
# 1. Clone the repository
$ git clone https://github.com/your-username/doctor-patient-system.git
$ cd doctor-patient-system/app2

# 2. (Optional) Create virtual environment
$ python3 -m venv venv
$ source venv/bin/activate  # On Windows: venv\Scripts\activate

# 3. Install requirements
$ pip install -r requirements.txt

# 4. Set up environment variables
$ cp .env.example .env  # Then add your Gemini API key

# 5. Run the application
$ streamlit run app.py
```

---

## ▶️ Usage

After launching the app, go to `http://localhost:8501`.

### 👨‍⚕️ Doctors:
- Login or register
- View all patients and message them
- View Gemini AI suggestions and add your own medical comments

### 👤 Patients:
- Login or register
- Start new conversations with your doctor
- Get instant AI insights on your symptoms

---

## 🧠 AI Integration

Gemini API (Google Generative AI) is used to:
- Analyze patient messages
- Offer suggestions for diagnosis or next steps
- Help doctors accelerate patient evaluation

Requires the following in your `.env` file:
```bash
GOOGLE_API_KEY=your_gemini_api_key_here
```

---

## 🗃️ Database Schema

SQLite file: `doctor_patient_system.db`

### `users` table
| Field | Type | Description |
|-------|------|-------------|
| id | INTEGER | Primary Key |
| username | TEXT | Unique login |
| password_hash | TEXT | Hashed password |
| user_type | TEXT | 'doctor' or 'patient' |
| created_at | TIMESTAMP | Registered date |

### `conversations` table
| Field | Type | Description |
|-------|------|-------------|
| id | INTEGER | Primary Key |
| patient_id | INTEGER | Linked to users.id |
| doctor_id | INTEGER | Linked to users.id |
| message | TEXT | User message |
| sender_type | TEXT | 'doctor' or 'patient' |
| ai_analysis | TEXT | Gemini AI output |
| ai_doctor_analysis | TEXT | Doctor's own analysis |
| timestamp | TIMESTAMP | Date of message |

---

## 📦 Requirements

- Python 3.7+
- Streamlit
- sqlite3
- python-dotenv
- google-generativeai
- plotly

---

## 📄 License

This project is licensed under the MIT License.

---
You can find a demo video of our app:
https://www.youtube.com/watch?v=CcJGd2CVfY8
---
Contributions, bug reports, and feedback are welcome!
