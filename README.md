# 🛡️ Cyber-Sentinel: Advanced Network Sniffer

## 📌 Overview
Cyber-Sentinel is a powerful, real-time Full-Stack Network Packet Sniffer and Traffic Analyzer. It captures live network packets, resolves domain names, detects geographic locations, and visualizes the traffic distribution using a modern React-based web dashboard.

## ✨ Key Features
* **Real-time Packet Capturing:** Uses Python's `Scapy` to intercept live network traffic.
* **DNS Resolution:** Automatically resolves IP addresses to their human-readable Domain Names (e.g., google.com).
* **Geo-Location Tracking:** Identifies the origin country of incoming and outgoing packets.
* **Threat Detection:** Flags suspicious IPs if they exceed a certain traffic threshold.
* **Live Dashboard Visualization:** React.js frontend with `Recharts` for real-time Pie Chart distribution of TCP/UDP protocols.
* **Control Panel:** Start, Stop, and Clear data directly from the web UI.

## 🛠️ Tech Stack
* **Backend:** Python, Flask, Scapy, Socket
* **Frontend:** React.js, Vite, Recharts
* **API Communication:** RESTful API with Flask-CORS

## 🚀 How to Run Locally

### 1. Start the Backend (Python)
Navigate to the root directory and install dependencies:
`pip install flask flask-cors scapy requests`

Run the engine:
`python sniffer.py`

### 2. Start the Frontend (React)
Open a new terminal, navigate to the UI folder:
`cd sniffer-ui`

Install Node modules and start the Vite server:
`npm install`
`npm run dev`

### 3. View the Dashboard
Open your browser and visit `http://localhost:5173/` (or the port provided by Vite).
