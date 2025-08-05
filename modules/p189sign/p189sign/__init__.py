#!/usr/bin/env python3
# encoding: utf-8

__author__ = "ChenyangGao <https://chenyanggao.github.io>"
__license__ = "GPLv3 <https://www.gnu.org/licenses/gpl-3.0.txt>"
__version__ = (0, 0, 10)
__all__ = ["make_signed_headers", "make_hmac_signed_headers", "make_encrypted_params_headers"]

from base64 import b64encode
from collections.abc import Iterable, Mapping
from datetime import datetime
from hashlib import md5
from hmac import digest as hmac_digest
from time import time
from urllib.parse import urlsplit

from .util import aes_ecb_encrypt, rsa_encrypt_with_perm, urlencode


def make_signed_headers(
    auth_headers: str | Mapping[str, str] | Iterable[tuple[str, str]], 
    payload: None | Mapping[str, str] | Iterable[tuple[str, str]] = None, 
    headers: None | Mapping[str, str] | Iterable[tuple[str, str]] = None, 
) -> dict[str, str]:
    """制作携带签名的请求头，专供基于 "AccessToken" 请求头的访问

    :param auth_headers: 访问令牌 或者 与签名有关的请求头
    :param payload: 请求参数
    :param headers: 其它的请求头字段

    :return: 加上签名的请求头字典
    """
    if isinstance(auth_headers, str):
        auth_headers = {"AccessToken": auth_headers}
    else:
        auth_headers = dict(auth_headers)
    auth_headers.setdefault("Timestamp", str(int(time() * 1000)))
    payload = dict(payload or (), **auth_headers)
    signature = md5(urlencode(sorted(payload.items())).encode("utf-8")).hexdigest()
    return dict(
        headers or (), 
        **auth_headers, 
        **{"Sign-Type": "1", "Signature": signature}, 
    )


def make_hmac_signed_headers(
    session_key: str, 
    session_secret: str, 
    url: str, 
    method: str = "GET", 
    headers: None | Mapping[str, str] | Iterable[tuple[str, str]] = None, 
):
    """制作携带签名的请求头，专供基于 "SessionKey" 请求头的访问

    :param session_key: 会话 key
    :param session_secret: 会话密码
    :param url: 请求链接
    :param method: 请求方法
    :param headers: 其它的请求头字段

    :return: 加上签名的请求头字典
    """
    date = datetime.now().strftime("%y-%m-%d%H:%M:%S")
    signature = hmac_digest(
        bytes(session_secret, "ascii"), 
        urlencode({
            "SessionKey": session_key, 
            "Operate": method.upper(), 
            "RequestURI": urlsplit(url).path, 
            "Date": date, 
        }).encode("utf-8"), 
        "sha1"
    ).hex().upper()
    return dict(
        headers or (), 
        **{
            "Date": date,
            "SessionKey": session_key,
            "Signature": signature, 
        }
    )


def make_encrypted_params_headers(
    session_key: str, 
    url: str, 
    method: str = "GET", 
    payload: None | Mapping[str, str] | Iterable[tuple[str, str]] = None, 
    headers: None | Mapping[str, str] | Iterable[tuple[str, str]] = None, 
    pkid: None | str = None, 
    pubkey = None, 
) -> tuple[dict, dict]:
    """对请求参数进行 AES 加密，然后返回加密后的请求参数和相应的请求头

    :param session_key: 会话 key
    :param pubkey: 公钥
    :param pkid: 私钥 id
    :param url: 请求链接
    :param method: 请求方法
    :param payload: 请求参数
    :param headers: 其它的请求头字段

    :return: 加密后的请求参数和相应的请求头的元组
    """
    aes_key = b"0" * 16
    if payload:
        params = aes_ecb_encrypt(urlencode(payload).encode("utf-8"), aes_key).hex()
    else:
        params = "346bce0b8eed34da10f6a8fabb844494"
    timestamp = str(int(time() * 1000))
    if pubkey:
        encrypted_key = b64encode(rsa_encrypt_with_perm(aes_key, pubkey)).decode("ascii")
    else:
        encrypted_key = "WS+7/J9D2JG7/8OpDwT84XTqpMIgwYCj2T9ffLVEoFtvBUetFkX2D6LNc9ctcS19uMiQ2DtXNRRDQOw4YouzbQt2jsgX/1UODAGolRDaZutVKkrG/U4hyNResJ+y929QzAXgv0GjhgGjfx1v+nr/rTppjKok63zBKIb+vaSz1UA="
    headers = dict(headers or ())
    if pkid:
        headers["PkId"] = pkid
    headers.update({
        "EncryptionText": encrypted_key, 
        "SessionKey": session_key, 
        "Signature": hmac_digest(
            aes_key, 
            urlencode({
                "SessionKey": session_key, 
                "Operate": method.upper(), 
                "RequestURI": urlsplit(url).path, 
                "Date": timestamp, 
                "params": params, 
            }).encode("utf-8"), 
            "sha1", 
        ).hex(), 
        "X-Request-Date": timestamp, 
    })
    return {"params": params}, headers

