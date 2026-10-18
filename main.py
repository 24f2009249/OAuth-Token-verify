import jwt
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI()

# Your exact assigned values from the grader
EXPECTED_ISSUER = "https://idp.exam.local"
EXPECTED_AUDIENCE = "tds-int741g8.apps.exam.local"

# Fixed public key with the correct base64 character (/)
PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2okOHspNjG+2rTLbeuY
cxIP/HG8C6sb9iwg3yiAA4HCNpITcbkCselbvbYGu3EbNy4xFyf5cbJ5DHJMlD
EkryOgdy2GiiIIBOUj8S63uGCnRPObH9NFatfNwheKuzsPuN1du6A9cNtEnpXc
WyjJG2axvfmq7i65ukr13oWYG7xTTAuKPujS14otzqfD3h5NepzdFXpr280NnzFw
ed+zclR68cmNNo/kWF34x/yCLSf08COGDTgW6PdaChd119VdetJzvEgC5tkyUxsFI
SI6iyrvbK80NEBSqq4XkadeJsCs4F1Rcnss4Llgmit7GlkL9Mce3b0wGLs9/7ZIX
dQIDAQAB
-----END PUBLIC KEY-----"""

class TokenRequest(BaseModel):
    token: str

@app.post("/verify")
async def verify_token(payload: TokenRequest):
    try:
        # Decode and verify the JWT against all rules (Signature, iss, aud, exp)
        decoded_payload = jwt.decode(
            payload.token,
            PUBLIC_KEY,
            algorithms=["RS256"],
            audience=EXPECTED_AUDIENCE,
            issuer=EXPECTED_ISSUER,
            options={"verify_exp": True}
        )
        
        # On valid token, return 200 with required echoed claims
        return {
            "valid": True,
            "email": decoded_payload.get("email"),
            "sub": decoded_payload.get("sub"),
            "aud": decoded_payload.get("aud")
        }
    except Exception as e:
        # On any invalid token (signature fail, expired, wrong audience, tampered), return 401
        raise HTTPException(
            status_code=401,
            detail={"valid": False}
        )