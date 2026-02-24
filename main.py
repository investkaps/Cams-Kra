import os
import re
import json
import base64
import time
import requests
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel, field_validator
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from dotenv import load_dotenv

# ================= LOAD ENV =================

load_dotenv()

TOKEN_URL = "https://camskra.com/restAuth/api/v1/getToken"
PAN_DOWNLOAD_URL = "https://camskra.com/CAMSWS_KRA/KRA_API/PANdownload"

CLIENT_CODE = os.getenv("CLIENT_CODE")
CLIENT_ID = os.getenv("CLIENT_ID")
SECRET_KEY = os.getenv("SECRET_KEY")
API_KEY = os.getenv("API_KEY")

enc_key = os.getenv("ENC_DEC_KEY")
iv_key = os.getenv("IV_KEY")

if not all([CLIENT_CODE, CLIENT_ID, SECRET_KEY, API_KEY, enc_key, iv_key]):
    raise RuntimeError("Missing required environment variables")

# Decode encryption keys
ENC_DEC_KEY = base64.b64decode(enc_key)
IV_KEY = base64.b64decode(iv_key)

# Validate key sizes
if len(ENC_DEC_KEY) != 32:
    raise RuntimeError("ENC_DEC_KEY must decode to 32 bytes (AES-256)")

if len(IV_KEY) != 16:
    raise RuntimeError("IV_KEY must decode to 16 bytes")

# ================= TOKEN CACHE =================

cached_token: Optional[str] = None
token_expiry: float = 0

# ================= FASTAPI =================

app = FastAPI(title="CAMS PAN Download API")

# ================= MODELS =================

class PanRequest(BaseModel):
    pan: str
    dob: str  # DD-MM-YYYY

    @field_validator("pan")
    @classmethod
    def validate_pan(cls, v):
        v = v.strip().upper()
        if not re.match(r"^[A-Z]{5}[0-9]{4}[A-Z]$", v):
            raise ValueError("Invalid PAN format")
        return v

    @field_validator("dob")
    @classmethod
    def validate_dob(cls, v):
        try:
            datetime.strptime(v, "%d-%m-%Y")
            return v
        except ValueError:
            raise ValueError("DOB must be in DD-MM-YYYY format")

# ================= AES ENCRYPTION =================

def encrypt_payload(payload: dict) -> str:
    data = json.dumps(payload).encode("utf-8")

    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()

    cipher = Cipher(
        algorithms.AES(ENC_DEC_KEY),
        modes.CBC(IV_KEY),
        backend=default_backend()
    )

    encryptor = cipher.encryptor()
    encrypted = encryptor.update(padded) + encryptor.finalize()

    return base64.b64encode(encrypted).decode("utf-8")


def decrypt_payload(data: str) -> dict:
    encrypted = base64.b64decode(data)

    cipher = Cipher(
        algorithms.AES(ENC_DEC_KEY),
        modes.CBC(IV_KEY),
        backend=default_backend()
    )

    decryptor = cipher.decryptor()
    padded = decryptor.update(encrypted) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    decrypted = unpadder.update(padded) + unpadder.finalize()

    return json.loads(decrypted.decode("utf-8"))

# ================= TOKEN FUNCTION =================

def get_token():
    global cached_token, token_expiry

    if cached_token and time.time() < token_expiry:
        return cached_token

    payload = {
        "clientCode": CLIENT_CODE,
        "grantType": "client_credentials",
        "scope": "KYC"
    }

    response = requests.post(
        TOKEN_URL,
        json=payload,
        auth=(CLIENT_ID, SECRET_KEY),
        timeout=15
    )

    response.raise_for_status()
    data = response.json()

    if data.get("returnCode") not in (None, "0"):
        raise Exception(data.get("returnMsg", "Token error"))

    token = data.get("accessToken")
    if not token:
        raise Exception("Token not returned")

    token_expiry = time.time() + (18 * 60)
    cached_token = token

    return token

# ================= PAN DOWNLOAD =================

def pan_download(pan: str, dob: str) -> dict:
    token = get_token()

    payload = {
        "PAN": [{
            "pan": pan,
            "dob": dob
        }],
        "sign_required": "N"
    }

    encrypted = encrypt_payload(payload)

    headers = {
        "Authorization": f"Bearer {token}",
        "ClientId": CLIENT_ID,
        "Content-Type": "application/json"
    }

    response = requests.post(
        PAN_DOWNLOAD_URL,
        json={"data": encrypted},
        headers=headers,
        timeout=20
    )

    if response.status_code == 401:
        global cached_token
        cached_token = None
        token = get_token()
        headers["Authorization"] = f"Bearer {token}"

        response = requests.post(
            PAN_DOWNLOAD_URL,
            json={"data": encrypted},
            headers=headers,
            timeout=20
        )

    response.raise_for_status()
    response_json = response.json()

    if "data" not in response_json:
        raise Exception("Invalid response from CAMS")

    return decrypt_payload(response_json["data"])

# ================= ROUTES =================

@app.post("/pan-download")
def pan_download_api(
    request: PanRequest,
    x_api_key: str = Header(None)
):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")

    try:
        result = pan_download(request.pan, request.dob)
        return {
            "success": True,
            "pan": request.pan,
            "data": result
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/")
def health():
    return {"status": "CAMS PAN Download API running"}

# ================= LOCAL RUN =================

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8080))
    uvicorn.run(app, host="0.0.0.0", port=port)
