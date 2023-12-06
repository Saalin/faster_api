import os
import requests

from typing import Union

from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from pydantic import BaseModel

import os
import json
import httpx
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import OAuth2PasswordBearer
from fastapi import Request
import jwt
from jwt import PyJWKClient
from jose import jwk

from dotenv import load_dotenv

load_dotenv()

COGNITO_DOMAIN = os.environ.get("COGNITO_DOMAIN")
COGNITO_CLIENT_ID = os.environ.get("COGNITO_CLIENT_ID")
COGNITO_CLIENT_SECRET = os.environ.get("COGNITO_CLIENT_SECRET")
COGNITO_REDIRECT_URI = os.environ.get("COGNITO_REDIRECT_URI")
COGNITO_REGION = os.environ.get("COGNITO_REGION")
COGNITO_USER_POOL_ID =  os.environ.get("COGNITO_USER_POOL_ID")
COGNITO_LOGOUT_URI = "http://localhost:8000"

AUTH_URL = f"https://{COGNITO_DOMAIN}/oauth2/authorize"
TOKEN_URL = f"https://{COGNITO_DOMAIN}/oauth2/token"
USERINFO_URL = f"https://{COGNITO_DOMAIN}/oauth2/userInfo"
LOGOUT_URL = f"https://{COGNITO_DOMAIN}/logout"

async def get_cognito_jwt_secret() -> str:
    JWKS_URL = f"https://cognito-idp.{COGNITO_REGION}.amazonaws.com/{COGNITO_USER_POOL_ID}/.well-known/jwks.json"

    async with httpx.AsyncClient() as client:
        response = await client.get(JWKS_URL)

    if response.status_code != 200:
        raise Exception("Failed to fetch JWKS from Cognito")

    jwks = response.json()
    for key_data in jwks["keys"]:
        if key_data["alg"] == "RS256" and key_data["use"] == "sig":
            key = jwk.construct(key_data)
            return key.to_pem().decode("utf-8")

    raise Exception("Failed to find a suitable public key in JWKS")

async def get_token(request: Request):
    token = request.cookies.get('access_token')
    
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token is required")
    return (token, request.cookies.get('refresh_token'))

async def get_current_user(token: str = Depends(get_token)) -> str:
    JWKS_URL = f"https://cognito-idp.{COGNITO_REGION}.amazonaws.com/{COGNITO_USER_POOL_ID}/.well-known/jwks.json"
    client = PyJWKClient(JWKS_URL)

    (access_token, refresh_token) = token

    try:
        header = jwt.get_unverified_header(access_token)
        key = client.get_signing_key(header["kid"])
        public_key = key.key
        payload = jwt.decode(access_token, public_key, algorithms=["RS256"])
        return payload["sub"]
    except jwt.ExpiredSignatureError:
        
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has expired")
    except jwt.JWTClaimsError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token claims")
    except jwt.JWTError:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid token")

app = FastAPI(debug="Hello")

class Item(BaseModel):
    name: str
    price: float
    is_offer: Union[bool, None] = None


@app.get("/items/{item_id}")
def read_item(item_id: int, q: Union[str, None] = None):
    return {"item_id": item_id, "q": q}

@app.put("/items/{item_id}")
def update_item(item_id: int, item: Item):
    return {"item_name": item.name, "item_id": item_id}

@app.get("/", response_class=HTMLResponse)
async def login():
    return f"""
    <html>
        <head>
            <title>Login</title>
        </head>
        <body>
            <form action="{AUTH_URL}" method="get">
                <input type="hidden" name="response_type" value="code" />
                <input type="hidden" name="client_id" value="{COGNITO_CLIENT_ID}" />
                <input type="hidden" name="redirect_uri" value="{COGNITO_REDIRECT_URI}" />
                <input type="submit" value="Login with AWS Cognito" />
            </form>
        </body>
    </html>
    """
    
@app.get("/callback")
async def callback(code: str):
    data = {
        "grant_type": "authorization_code",
        "client_id": COGNITO_CLIENT_ID,
        "client_secret":COGNITO_CLIENT_SECRET,
        "code": code,
        "redirect_uri": COGNITO_REDIRECT_URI,
    }
    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
        }
    async with httpx.AsyncClient() as client:
        response = await client.post(TOKEN_URL, data=data, headers=headers)
        
    if response.status_code != 200:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid code")
    token = response.json()
  
    response = RedirectResponse(url=f"/chatbot")
    response.set_cookie(key="access_token", value=token['access_token'], domain="localhost", secure=False)
    response.set_cookie(key="refresh_token", value=token['refresh_token'], domain="localhost", secure=False)
    return response


@app.get("/chatbot", response_class=HTMLResponse)
async def chatbot(request: Request, sub: str = Depends(get_current_user)):
    token = request.cookies.get('access_token')
    
    user_info = get_user_info(token, USERINFO_URL)
    
    return f"""
    <html>
        <head>
            <title>Chatbot</title>
        </head>
        <body>
            <h1>Welcome, {sub}!</h1>
            <p>{user_info}</p>
            <p>Here you can chat with the robot.</p>
        </body>
    </html>
    """
    
@app.get("/logout")
async def logout(request: Request):
    token = request.cookies.get('access_token')
    return RedirectResponse(url=f"{LOGOUT_URL}?client_id={COGNITO_CLIENT_ID}&logout_uri={COGNITO_LOGOUT_URI}")

def get_user_info(access_token, userinfo_endpoint):
    import requests
    
    headers = {
        "Authorization": f"Bearer {access_token}"
    }

    response = requests.get(userinfo_endpoint, headers=headers)

    if response.status_code == 200:
        user_info = response.json()
        return user_info
    else:
        # Handle errors
        print(f"Error: {response.status_code}")
        print(response.text)

def refresh_token(refresh_token):
    import requests
    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }

    data = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": COGNITO_CLIENT_ID,
        "client_secret": COGNITO_CLIENT_SECRET
        # Add other parameters as needed (e.g., redirect_uri)
    }

    response = requests.post(TOKEN_URL, headers=headers, data=data)

    if response.status_code == 200:
        token_data = response.json()
        new_access_token = token_data.get("access_token")
        new_refresh_token = token_data.get("refresh_token")

        return (new_access_token, new_refresh_token)
    else:
        return None
