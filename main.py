import base64
import hashlib
import hmac
import time
from typing import Optional

import requests


class AuthenticationError(requests.ConnectionError):
    """Kimlik doğrulama hatası"""


class Client:

    publicKey: Optional[str]
    privateKey: Optional[str]

    authenticated: bool
    session: requests.Session

    def __init__(self, publicKey: Optional[str] = None, privateKey: Optional[str] = None):
        self.session = self._init_session()

        self.authenticated = False
        self.publicKey = publicKey
        self.privateKey = privateKey

        if publicKey and privateKey:
            self.authenticate()

    def _init_session(self) -> requests.Session:
        """Oturum oluşturma

        Returns:
            requests.Session -- Oturum objesi
        """
        session = requests.session()
        headers = {"Content-Type": "application/json"}
        session.headers.update(headers)
        return session

    def get_sample(self):
        url = ""
        params = {}
        self.session.get(url=url, params=params)

    def _create_signatureBytes(self) -> bytes:
        """HMAC-SHA256 ile şifrelenmiş mesaj oluşturma

        Gizli anahtar kullanılarak HMAC-SHA256 ile şifrelenmiş, açık anahtarı ve \
            sonunda zaman mührünü içeren imzayı oluşturur

        Returns:
            bytes: İmza
        """
        privateKey = base64.b64decode(self.privateKey)
        timestamp = self._create_timestampStr()
        data = f"{self.publicKey}{timestamp}".encode("utf-8")
        signature = hmac.new(privateKey, data, hashlib.sha256).digest()
        signature = base64.b64encode(signature)
        return signature

    def _create_timestampStr(self) -> str:
        return str(int(time.time() * 1000))

    def _create_signatureStr(self) -> str:
        return str(self._create_signatureBytes().decode("utf-8"))

    def _update_session_headers(self):
        """Session header verilerini günceller

        HMAC-SHA256 mesajları zamana bağlıdır, yetki gerektiren işlemler için \
            zaman mührünün yenilenmesi gerekir
        """
        self.session.headers.update({
            "X-Stamp": self._create_timestampStr(),
            "X-Signature": self._create_signatureStr()
        })

    def authenticate(self):
        url = ""  # TODO: Auth url
        signature = self._create_signatureStr() # Signature daha önce alınmalı
        headers = {
            "X-PCK": self.publicKey,
            "X-Stamp": self._create_timestampStr(),
            "X-Signature": signature
        }
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            self.authenticated = True
            self.session.headers.update({"X-PCK": self.publicKey})
        else:
            raise AuthenticationError(response)

    def get_sample_auth(self):
        self._update_session_headers()
        return self.get_sample()
