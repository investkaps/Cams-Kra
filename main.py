import os
import re
import json
import base64
import time
import requests
import smtplib

from datetime import datetime
from typing import Optional

from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel, field_validator
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from dotenv import load_dotenv

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication


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


# ================= SMTP =================

SMTP_HOST = os.getenv("SMTP_HOST")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASS = os.getenv("SMTP_PASS")
EMAIL_TO = os.getenv("EMAIL_TO")


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


# ================= MODELS =================

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

    if enc_key and iv_key:

        ENC_DEC_KEY = base64.b64decode(enc_key)
        IV_KEY = base64.b64decode(iv_key)

    else:
        print("Encryption keys missing")


def validate_env():

    if not all([
        CLIENT_CODE,
        CLIENT_ID,
        SECRET_KEY,
        API_KEY,
        ENC_DEC_KEY,
        IV_KEY
    ]):
        raise HTTPException(status_code=500, detail="Server configuration error")


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


# ================= EMAIL XML =================

def send_xml_email(pan: str, xml_data: str):

    if not SMTP_HOST or not EMAIL_TO:
        return

    msg = MIMEMultipart()

    msg["From"] = SMTP_USER
    msg["To"] = EMAIL_TO
    msg["Subject"] = f"CAMS KYC XML {pan}"

    msg.attach(MIMEText("CAMS KYC XML attached.", "plain"))

    attachment = MIMEApplication(xml_data.encode("utf-8"))

    attachment.add_header(
        "Content-Disposition",
        "attachment",
        filename=f"{pan}_kyc.xml"
    )

    msg.attach(attachment)

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:

        server.starttls()

        server.login(SMTP_USER, SMTP_PASS)

        server.send_message(msg)


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


# ================= PAN DOWNLOAD =================

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


# ================= ROUTE =================

@app.post("/pan-download")
def pan_download_api(request: PanRequest, x_api_key: str = Header(None)):

    validate_env()

    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")

    result = pan_download(request.pan, request.dob)

    try:

        kyc_list = result.get("kycData", [])

        if not kyc_list:
            raise Exception("No KYC data returned")

        pan_data = kyc_list[0]

        status_code = str(pan_data.get("status", "")).strip()

        if not status_code:
            raise Exception("Missing KYC status")

    except Exception:
        raise HTTPException(status_code=500, detail="Invalid CAMS response")

    status_desc = KYC_STATUS_MAP.get(status_code, "UNKNOWN")

    # ================= SUCCESS =================

    if status_code in ["02", "07", "12", "22"]:

        xml_data = pan_data.get("signature", "")

        if xml_data:

            try:
                send_xml_email(request.pan, xml_data)
            except Exception as e:
                print("Email error:", str(e))

        return {
            "success": True,
            "status_code": status_code,
            "status": status_desc,
            "pan": request.pan,
            "data": pan_data
        }

    # ================= NOT AVAILABLE =================

    if status_code == "05":

        return {
            "success": False,
            "status_code": "05",
            "status": "NOT_AVAILABLE",
            "message": "PAN record not available in KRA"
        }

    # ================= REJECTED =================

    if status_code in ["04", "14"]:

        return {
            "success": False,
            "status_code": status_code,
            "status": "KYC_REJECTED",
            "message": "KYC rejected by KRA"
        }

    # ================= OTHER STATES =================

    return {
        "success": False,
        "status_code": status_code,
        "status": status_desc,
        "message": f"KYC status: {status_desc}"
    }


# ================= HEALTH =================

@app.get("/")
def health():

    return {
        "status": "CAMS PAN Download API running"
    }


# ================= LOCAL RUN =================

if __name__ == "__main__":

    import uvicorn

    port = int(os.environ.get("PORT", 8080))

    uvicorn.run(app, host="0.0.0.0", port=port)
