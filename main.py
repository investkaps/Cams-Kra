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


# ================= INIT =================

load_dotenv()

app = FastAPI(title="CAMS PAN Download API")

TOKEN_URL = "https://camskra.com/restAuth/api/v1/getToken"
PAN_DOWNLOAD_URL = "https://camskra.com/CAMSWS_KRA/KRA_API/PANdownload"

CLIENT_CODE = os.getenv("CLIENT_CODE")
CLIENT_ID = os.getenv("CLIENT_ID")
SECRET_KEY = os.getenv("SECRET_KEY")
API_KEY = os.getenv("API_KEY")

ENC_DEC_KEY: Optional[bytes] = None
IV_KEY: Optional[bytes] = None

cached_token: Optional[str] = None
token_expiry: float = 0


# ================= STATUS MAP =================

KYC_STATUS_MAP = {
    "01": "UNDER_PROCESS",
    "02": "KYC_REGISTERED",
    "03": "ON_HOLD",
    "04": "KYC_REJECTED",
    "05": "NOT_AVAILABLE",
    "06": "DEACTIVATED",
    "07": "KYC_VALIDATED",
    "11": "UNDER_PROCESS",
    "12": "KYC_REGISTERED",
    "13": "ON_HOLD",
    "14": "KYC_REJECTED",
    "22": "MUTUAL_FUND_VERIFIED"
}

VERIFIED_CODES = ["02", "07", "12", "22"]


# ================= REQUEST MODEL =================

class PanRequest(BaseModel):
    pan: str
    dob: str

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
            raise ValueError("DOB must be DD-MM-YYYY")


# ================= STARTUP =================

@app.on_event("startup")
def initialize_keys():

    global ENC_DEC_KEY, IV_KEY

    enc_key = os.getenv("ENC_DEC_KEY")
    iv_key = os.getenv("IV_KEY")

    if not enc_key or not iv_key:
        raise Exception("Encryption keys missing")

    ENC_DEC_KEY = base64.b64decode(enc_key)
    IV_KEY = base64.b64decode(iv_key)


# ================= ENCRYPTION =================

def encrypt_payload(payload: dict) -> str:

    data = json.dumps(payload).encode()

    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()

    cipher = Cipher(
        algorithms.AES(ENC_DEC_KEY),
        modes.CBC(IV_KEY),
        backend=default_backend()
    )

    encryptor = cipher.encryptor()

    encrypted = encryptor.update(padded) + encryptor.finalize()

    return base64.b64encode(encrypted).decode()


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

    return json.loads(decrypted.decode())


# ================= TOKEN =================

def get_token():

    global cached_token, token_expiry

    if cached_token and time.time() < token_expiry:
        return cached_token

    response = requests.post(
        TOKEN_URL,
        json={
            "clientCode": CLIENT_CODE,
            "grantType": "client_credentials",
            "scope": "KYC"
        },
        auth=(CLIENT_ID, SECRET_KEY),
        timeout=15
    )

    response.raise_for_status()

    data = response.json()

    token = data.get("accessToken")

    if not token:
        raise Exception("Token not returned")

    token_expiry = time.time() + (18 * 60)

    cached_token = token

    return token


# ================= CAMS PAN DOWNLOAD =================

def pan_download(pan: str, dob: str):

    token = get_token()

    encrypted = encrypt_payload({
        "PAN": [{"pan": pan, "dob": dob}],
        "sign_required": "N"
    })

    response = requests.post(
        PAN_DOWNLOAD_URL,
        json={"data": encrypted},
        headers={
            "Authorization": f"Bearer {token}",
            "ClientId": CLIENT_ID,
            "Content-Type": "application/json"
        },
        timeout=20
    )

    if response.status_code == 401:

        global cached_token
        cached_token = None

        return pan_download(pan, dob)

    response.raise_for_status()

    response_json = response.json()

    if "data" not in response_json:
        raise Exception("Invalid response from CAMS")

    return decrypt_payload(response_json["data"])


# ================= STATUS EXTRACTION =================

def extract_pan_record(result):

    if "kycData" in result and result["kycData"]:
        return result["kycData"][0]

    if "verifyPanResponseList" in result and result["verifyPanResponseList"]:
        return result["verifyPanResponseList"][0]

    if "PAN" in result and result["PAN"]:
        return result["PAN"][0]

    return None


# ================= API ROUTE =================

@app.post("/pan-download")
def pan_download_api(request: PanRequest, x_api_key: str = Header(None)):

    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")

    result = pan_download(request.pan, request.dob)

    pan_data = extract_pan_record(result)

    if not pan_data:
        return {
            "success": False,
            "status_code": None,
            "data": result
        }

    status_code = str(
        pan_data.get("status")
        or pan_data.get("updateStatus")
        or pan_data.get("kycStatus")
        or pan_data.get("camskra")
        or pan_data.get("compStatus")
        or ""
    ).strip()

    return {
        "success": status_code in VERIFIED_CODES,
        "status_code": status_code if status_code else None,
        "pan": request.pan,
        "data": result
    }


# ================= HEALTH =================

@app.get("/")
def health():
    return {"status": "CAMS PAN Download API running"}
