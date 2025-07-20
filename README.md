# 🛡️ Malvisor - ML-Powered Static Malware Analysis Platform

[![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![React](https://img.shields.io/badge/React-18+-61DAFB?style=for-the-badge&logo=react&logoColor=black)](https://reactjs.org)
[![Flask](https://img.shields.io/badge/Flask-2.0+-000000?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com)
[![Vite](https://img.shields.io/badge/Vite-4.0+-646CFF?style=for-the-badge&logo=vite&logoColor=white)](https://vitejs.dev)
[![TailwindCSS](https://img.shields.io/badge/Tailwind_CSS-3.0+-38B2AC?style=for-the-badge&logo=tailwind-css&logoColor=white)](https://tailwindcss.com)
[![LightGBM](https://img.shields.io/badge/LightGBM-ML_Model-brightgreen?style=for-the-badge)](https://lightgbm.readthedocs.io)

> 🔍 A comprehensive static malware analysis platform powered by machine learning that provides deep insights into Windows PE files and DLLs with intelligent threat detection and severity scoring.

## 🌟 Overview

**Malvisor** is an advanced static malware analysis platform that combines the power of machine learning with comprehensive file analysis to detect and classify various types of malware. Built with modern web technologies and powered by Google's Gemini AI, it provides security researchers, analysts, and developers with a robust tool for malware detection and analysis.

## ✨ Key Features

### 📁 File Analysis Engine
- **🎯 Targeted File Support**: Accepts only PE (Portable Executable) files and DLLs for focused Windows malware analysis
- **⚡ Static Analysis**: Performs comprehensive static analysis without executing potentially harmful files
- **🔬 Deep Feature Extraction**: Extracts critical static features for ML-based classification

### 🤖 Machine Learning Detection
- **🧠 LightGBM Model**: Utilizes advanced gradient boosting for accurate malware classification
- **📊 Multi-Class Classification**: Detects 10 different malware families and benign files
- **🎯 High Accuracy**: Trained on extensive datasets for reliable threat detection

### 📈 Comprehensive Reporting
- **📋 Detailed Analysis Reports**: In-depth analysis with extracted features and classifications
- **⭐ Severity Scoring**: Intelligent severity assessment based on threat level
- **💾 Downloadable Reports**: Export analysis results in PDF format for documentation
- **🤖 AI-Powered Insights**: Gemini AI integration for interactive report analysis

## 🦠 Detected Malware Families

Malvisor can identify the following malware categories:

| 🏷️ Category | 📝 Description | 🚨 Severity Level |
|-------------|----------------|------------------|
| 🔒 **Ransomware** | Encrypts user data for ransom | 🔴 Critical |
| 🐴 **Trojan** | Disguised malicious software | 🟠 High |
| 🐛 **Worm** | Self-replicating network spreader | 🟠 High |
| 📺 **Adware** | Unwanted advertisement software | 🟡 Medium |
| 👁️ **Spyware** | Covert information gathering | 🟠 High |
| 🚪 **Backdoor** | Unauthorized remote access | 🔴 Critical |
| ⌨️ **Keylogger** | Keystroke monitoring software | 🟠 High |
| 📦 **Dropper** | Malware delivery mechanism | 🟠 High |
| 🌿 **Rootkit** | System-level hiding malware | 🔴 Critical |
| ✅ **Benign** | Safe, legitimate software | 🟢 Safe |

## 🔬 Static Feature Analysis

Malvisor extracts and analyzes the following critical features:

### 📊 **Structural Features**
- **`num_imports`** 📥: Number of imported functions and libraries
- **`section_count`** 📑: Count of PE file sections
- **`filesize`** 📏: File size in bytes

### 🔢 **Entropy Analysis**
- **`entropy_mean`** 📊: Average entropy across file sections
- **`entropy_max`** 📈: Maximum entropy value found
- **`entropy_min`** 📉: Minimum entropy value found

### 🔤 **String Analysis**
- **`string_count`** 📝: Total number of extracted strings
- **`suspicious_string_count`** ⚠️: Count of potentially malicious strings

These features are processed through our trained LightGBM model to provide accurate malware classification and threat assessment.

## 🛠️ Technology Stack

### 🎨 **Frontend**
- **React 18+** ⚛️: Modern component-based UI framework
- **Vite** ⚡: Next-generation frontend build tool for blazing fast development
- **TailwindCSS** 🎨: Utility-first CSS framework for rapid UI development

### 🔧 **Backend**
- **Flask** 🐍: Lightweight Python web framework for API development
- **LightGBM** 🤖: Gradient boosting framework for machine learning inference

### 🧠 **AI Integration**
- **Google Gemini API** 💎: Advanced AI for intelligent report analysis and interactive querying

## 📚 Core Libraries & Dependencies

### 🔍 **Analysis Libraries**
- **`pefile`** 📁: Python library for parsing PE (Portable Executable) files
  - Extracts headers, sections, imports, and metadata from Windows executables
  - Essential for structural analysis of PE files and DLLs

- **`string`** 🔤: Built-in Python module for string operations and constants
  - Used for extracting and analyzing printable strings from binary files
  - Helps identify suspicious text patterns and embedded URLs

- **`hashlib`** 🔐: Cryptographic hash functions library
  - Generates MD5, SHA1, SHA256 hashes for file identification
  - Creates unique fingerprints for malware samples

- **`capstone`** 🔧: Disassembly framework for multiple architectures
  - Disassembles x86/x64 machine code for static code analysis
  - Enables detection of malicious code patterns and behaviors

### 📄 **Report Generation**
- **`jspdf`** 📋: JavaScript library for PDF generation
  - Creates downloadable analysis reports in PDF format
  - Enables professional documentation of analysis results

- **`react-markdown`** 📝: React component for rendering Markdown content
  - Displays formatted analysis reports and documentation
  - Provides rich text rendering capabilities for better readability

## 🚀 Getting Started

### 📋 Prerequisites
- Node.js 16+ and npm
- Python 3.8+
- Google Gemini API key

### 🔧 Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/PrathicaShettyM/Malvisor.git
   ```

2. **Setup Frontend**
   ```bash
   cd client
   npm install
   npm run dev
   ```

3. **Setup Backend**
   ```bash
   cd server
   pip install -r requirements.txt
   python app.py
   ```

4. **Configure Environment**
   ```bash
   # Add your Gemini API key to environment variables
   export GEMINI_API_KEY=your_api_key_here
   ```

## 💡 Usage

1. **📤 Upload File**: Select and upload a PE file or DLL through the web interface
2. **⏳ Analysis**: The system automatically extracts static features and processes them through the ML model
3. **📊 Results**: View comprehensive analysis results including malware classification and severity score
4. **🤖 AI Insights**: Use the Gemini AI bot to ask questions about the analysis report
5. **💾 Export**: Download detailed PDF reports for documentation and further analysis

## 🔒 Security Features

- **🛡️ Safe Analysis**: Static analysis only - no file execution
- **🔍 Comprehensive Detection**: Multi-layered feature extraction and analysis
- **📈 Severity Assessment**: Intelligent threat level classification
- **🤖 AI-Enhanced**: Gemini AI provides additional insights and explanations

## 🤝 Contributing

We welcome contributions! Please feel free to submit issues, feature requests, or pull requests to help improve Malvisor.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

<div align="center">

**🛡️ Stay Safe, Analyze Smart with Malvisor! 🛡️**

Made by Prathica Shetty M

</div>