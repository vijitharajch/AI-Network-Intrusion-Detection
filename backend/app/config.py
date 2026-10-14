import os

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./nids.db")
MODEL_DIR = os.getenv("MODEL_DIR", "../models")
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",")
