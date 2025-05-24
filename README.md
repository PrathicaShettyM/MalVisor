# MalVisor
This is a all-in-one malware analysis platform 

malware-analyzer/
│
├── backend/                      # Flask + ML + Feature Extraction
│   ├── app.py                    # Entry point for Flask app
│   ├── requirements.txt          # Backend Python dependencies
│   ├── config.py                 # Configurations (CORS, paths, etc.)
│   ├── model/
│   │   ├── classifier.pkl        # Trained LightGBM model
│   │   └── extract_features.py   # Feature extraction logic
│   │
│   ├── routes/
│   │   └── scan.py               # /scan endpoint for file scan
│   │
│   ├── db/
│   │   ├── database.py           # SQLAlchemy setup
│   │   └── models.py             # DB models (ScanLog, etc.)
│   │
│   ├── utils/
│   │   └── helpers.py            # File validation, file save, etc.
│   │
│   └── uploads/                  # Temp folder to store uploaded files
│
├── frontend/                     # Next.js frontend
│   ├── app/                      # App directory (Next.js 13+)
│   ├── components/               # UI components
│   ├── pages/                    # For legacy routing if needed
│   ├── public/                   # Static files
│   ├── styles/                   # Tailwind CSS
│   └── tsconfig.json             # TypeScript config
│
├── .gitignore
└── README.md



# backend
cd server
python3 -m venv venv
venv\Scripts\activate

- Run the backend: `python app.py`



