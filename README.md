# 🔒 Privacy-Preserving User Registration & Authentication System

A secure web-based authentication system developed as part of my internship at the **Ministry of Electronics and Information Technology (MeitY), Government of India**. This project demonstrates the practical implementation of **Privacy Enhancing Technologies (PETs)** by protecting sensitive user information through encryption, hashing, secure authentication, and database activity monitoring.

---

## 📌 Project Overview

The project aims to provide a secure user registration and authentication system where sensitive personal information is protected using industry-standard security techniques.

Instead of storing user data in plain text, the system encrypts confidential information, hashes passwords, logs database activities, and ensures that only authenticated users can access and modify their own information.

---

## 🚀 Features

### 👤 User Module
- Secure User Registration
- User Login & Authentication
- View Profile
- Edit Profile
- Secure Logout

### 🔐 Privacy & Security Features
- AES Encryption for sensitive user data
- BCrypt Password Hashing
- Secure Password Verification
- Data Decryption for authenticated users
- Data Masking for sensitive information
- Secure Session Management
- Role-Based User Access

### 🗄️ Database Features
- MySQL Database Integration
- Stored Procedures for CRUD Operations
- Database Triggers
- Audit Logging System
- Activity Monitoring
- Record Modification Tracking

### 📊 Audit & Monitoring
- Tracks Login Activities
- Tracks Profile Updates
- Tracks Record Insertions
- Tracks Record Deletions
- Tracks Data Modifications
- Maintains Complete Audit Trail

---

# 🛡 Privacy Enhancing Technologies (PETs) Implemented

- AES Encryption
- BCrypt Password Hashing
- Data Masking
- Secure Authentication
- Database Activity Monitoring
- Audit Logging
- Access Control
- Privacy-Preserving Data Storage

---

# 🏗️ System Architecture

```
                User
                  │
                  ▼
        HTML • CSS • JavaScript
                  │
                  ▼
      Node.js + Express Backend
                  │
      ┌───────────┴───────────┐
      │                       │
      ▼                       ▼
AES Encryption          BCrypt Hashing
      │                       │
      └───────────┬───────────┘
                  ▼
          Stored Procedures
                  │
                  ▼
             MySQL Database
                  │
                  ▼
         Database Triggers
                  │
                  ▼
          Audit Logs Table
```

---

# 💻 Tech Stack

## Frontend

- HTML5
- CSS3
- JavaScript

## Backend

- Node.js
- Express.js

## Database

- MySQL
- MySQL Workbench

## Security

- AES Encryption
- BCrypt
- JWT Authentication
- Data Masking

## Database Security

- Stored Procedures
- Database Triggers
- Audit Logging

---

# 📂 Project Structure

```
project/
│
├── frontend/
│   ├── login.html
│   ├── register.html
│   ├── dashboard.html
│   ├── css/
│   └── js/
│
├── backend/
│   ├── controllers/
│   ├── routes/
│   ├── middleware/
│   ├── services/
│   ├── encryption/
│   ├── config/
│   └── server.js
│
├── database/
│   ├── schema.sql
│   ├── stored_procedures.sql
│   ├── triggers.sql
│   └── audit_logs.sql
│
├── screenshots/
│
└── README.md
```

---

# 📋 Database Tables

### users

- User ID
- Name (Encrypted)
- Email (Encrypted)
- Mobile (Encrypted)
- Address (Encrypted)
- Password (BCrypt Hashed)

### audit_logs

- Log ID
- User ID
- Username
- Action Type
- Table Name
- Record ID
- Previous Data
- Updated Data
- Timestamp
- IP Address
- Device Information

---

# ⚙️ Installation

## 1 Clone Repository

```bash
git clone https://github.com/yourusername/privacy-preserving-auth-system.git
```

---

## 2 Navigate to Project

```bash
cd privacy-preserving-auth-system
```

---

## 3 Install Dependencies

```bash
npm install
```

---

## 4 Configure MySQL

Create database

```sql
CREATE DATABASE pets_project;
```

Import

- schema.sql
- stored_procedures.sql
- triggers.sql

---

## 5 Configure Environment Variables

Create `.env`

```env
PORT=5000

DB_HOST=localhost
DB_USER=root
DB_PASSWORD=your_password
DB_NAME=pets_project

JWT_SECRET=your_secret_key

AES_SECRET_KEY=your_32_character_key
```

---

## 6 Start Server

```bash
npm start
```

or

```bash
npm run dev
```

---

# 📸 Screenshots

Add screenshots of:

- Login Page
- Registration Page
- Dashboard
- User Profile
- MySQL Database
- Audit Logs Table
- Encrypted Database Entries
- Activity Monitoring Dashboard

Example:

```
screenshots/
│
├── login.png
├── register.png
├── dashboard.png
├── profile.png
├── encrypted_db.png
├── audit_logs.png
```

---

# 🔐 Security Workflow

```
Registration
        │
        ▼
Encrypt Sensitive Data
        │
Hash Password
        │
Store in MySQL
        │
Create Audit Log
```

```
Login
      │
      ▼
Verify BCrypt Password
      │
Authenticate User
      │
Decrypt Personal Data
      │
Display Profile
```

---

# 🎯 Learning Outcomes

- Privacy Enhancing Technologies (PETs)
- Secure Authentication
- AES Encryption
- BCrypt Hashing
- Database Security
- MySQL Stored Procedures
- Database Triggers
- Audit Logging
- Activity Monitoring
- Secure User Management

---

# 🔮 Future Scope

- Multi-Factor Authentication (MFA)
- OAuth 2.0 / Google Login
- Fingerprint Authentication
- Face Recognition Login
- Role-Based Access Control (RBAC)
- End-to-End Encryption
- Cloud Database Deployment
- Docker Containerization
- CI/CD Pipeline
- AI-Based Suspicious Activity Detection
- Real-Time Security Dashboard
- Email & SMS Alerts for Suspicious Login Attempts

---

# 👩‍💻 Developed By

**Anushka Gupta**

B.Tech Information Technology  
Privacy Enhancing Technologies (PETs) Intern  
**Ministry of Electronics and Information Technology (MeitY), Government of India**

---

# 📜 License

This project is developed for educational and research purposes under the MeitY Privacy Enhancing Technologies (PETs) Internship Program.