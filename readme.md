# Python 天翼网盘客户端

![PyPI - Python Version](https://img.shields.io/pypi/pyversions/p189client)
![PyPI - Version](https://img.shields.io/pypi/v/p189client)
![PyPI - Downloads](https://img.shields.io/pypi/dm/p189client)
![PyPI - Format](https://img.shields.io/pypi/format/p189client)
![PyPI - Status](https://img.shields.io/pypi/status/p189client)

## 0. 安装

你可以从 [pypi](https://pypi.org/project/p189client/) 安装最新版本

```console
pip install -U p189client
```

## 1. 导入模块和创建实例

导入模块

```python
from p189client import P189Client, P189APIClient
```

`P189Client` 支持 2 种请求方式：

1. 请求头用 "Cookie"，不需要签名
2. 请求头用 "AccessToken"，需要签名

`P189APIClient` 支持 2 种请求方式

1. 请求头用 "SessionKey"，需要签名
2. 请求头用 "AccessToken"，需要签名

**温馨提示** `P189APIClient` 还在开发当中，接口补全，暂时不要使用

### 1. 人工扫码登录

什么都不传时，会输出一个二维码，要求你人工扫码登录

```python
client = P189Client()
api_client = P189APIClient()
```

### 2. 使用账号和密码登录

账号可以是邮箱或手机号，另外需要关闭设备锁。请在网页端登录天翼账号后，进行相关操作：

https://e.dlife.cn/user/index.do

```python
# TODO: 写下自己的账号和密码
username = "your_username"
password = "your_password"

client = P189Client(username, password)
api_client = P189APIClient(username, password)
```

### 3. 直接加载 `cookies`

`P189Client` 支持直接加载 `cookies`

```python
cookies = "..."

client = P189Client(cookies=cookies)
```

支持加载文件路径，这样当更新时，也会写入此文件中

```python
from pathlib import Path

client = P189Client(cookies=Path("~/189-cookies.txt").expanduser())
```

### 4. 直接加载 `session_data`

`P189APIClient` 支持直接加载 `session_data`

```python
session_data = {...}

api_client = P189APIClient(session_data=session_data)
```

支持加载文件路径，这样当更新时，也会写入此文件中

```python
from pathlib import Path

api_client = P189APIClient(session_data=Path("~/189-session-data.json").expanduser())
```

### 5. 使用 `session_key` 登录

`P189Client` 支持直接利用 `session_key` 来获取 `cookies`

```python
session_key = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

client = P189Client(session_key=session_key)
```

### 6. 使用 `token` 登录

`P189APIClient` 支持直接利用 `token` （`session_data` 中的 `accessToken`）来获取 `session_data`（除了 `refreshToken`）

```python
# 32 位小写的 16 进制，其实就是一个 UUID 的 16 进制表示
token = "..."

api_client = P189APIClient(token)
```

如果你存有一个 `refreshToken`，则需要先获取 `accessToken`，再获取 `session_data`

```python
# 32 位小写的 16 进制，其实也是一个 UUID 的 16 进制表示
refresh_token = "..."

api_client = P189APIClient(P189APIClient.login_with_refresh_token(refresh_token))
```

再结合上面的第 5 条，还可以用 `refresh_token` 来获取 cookies

```python
resp   = P189Client.login_with_refresh_token(refresh_token)
client = P189Client(resp["sessionKey"])
# 或者
client = P189Client(resp["familySessionKey"])
```

### 7. 使用 `SSO Cookie` 登录

有个 `Cookie` 字段是 "SSON"，往往在扫码登录或账号密码登录后获得，有效期不长，但是也可以用来获取 `session_data`，从而也能间接获得 `cookies`

```python
sso_cookie = "..."

api_client = P189APIClient(P189APIClient.login_with_sso_cookie(sso_cookie))
```

并且

```python
resp   = P189Client.login_with_sso_cookie(sso_cookie)
client = P189Client(resp["sessionKey"])
# 或者
client = P189Client(resp["familySessionKey"])
```

### 8 使用 `cookies` 扫码授权登录

除了用 `SSO Cookie`，理论上也能用普通的 `cookies` 授权登录，只需要模拟扫码点击确认即可，但目前我暂未实现这条

**TODO** 实现模拟扫码登录

## 2. 接口调用

所有需要直接或间接执行 HTTP 请求的接口，都有同步和异步的调用方式，且默认是采用 GET 发送请求数据

```python
# 同步调用
client.method(payload)
client.method(payload, async_=False)

# 异步调用
await client.method(payload, async_=True)
```

从根本上讲，除了几个 `staticmethod`，它们都会调用 `P189Client.request`

```python
url = "https://cloud.189.cn/api/someapi"
response = client.request(url=url, json={...})
```

当你需要构建自己的扩展模块，以增加一些新的天翼网盘的接口时，就需要用到此方法了

```python
from collections.abc import Coroutine
from typing import overload, Any, Literal

from p189client import P189Client

class MyCustom189Client(P189Client):

    @overload
    def foo(
        self, 
        payload: dict, 
        /, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def foo(
        self, 
        payload: dict, 
        /, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def foo(
        self, 
        payload: dict, 
        /, 
        async_: bool = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        api = "https://cloud.189.cn/api/foo"
        return self.request(
            api, 
            method="GET", 
            params=payload, 
            async_=async_, 
            **request_kwargs, 
        )

    @overload
    def bar(
        self, 
        payload: dict, 
        /, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def bar(
        self, 
        payload: dict, 
        /, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def bar(
        self, 
        payload: dict, 
        /, 
        async_: bool = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        api = "https://cloud.189.cn/api/bar"
        return self.request(
            api, 
            method="POST", 
            data=payload, 
            async_=async_, 
            **request_kwargs, 
        )
```

## 3. 检查响应

接口被调用后，如果返回的是 dict 类型的数据（说明原本是 JSON），则可以用 `p189client.check_response` 执行检查。如果检测为正常，则原样返回数据；否则，抛出一个 `p189client.P189OSError` 的实例。

```python
from p189client import check_response

# 检查同步调用
data = check_response(client.method(payload))
# 检查异步调用
data = check_response(await client.method(payload, async_=True))
```

## 4. 辅助工具

一些简单的封装工具可能是必要的，特别是那种实现起来代码量比较少，可以封装成单个函数的。我把平常使用过程中，积累的一些经验具体化为一组工具函数。这些工具函数分别有着不同的功能，如果组合起来使用，或许能解决很多问题。

```python
from p189client import tool
```

## 5. 学习案例

### 1. 直链服务

需要先安装 [blacksheep](https://www.neoteroi.dev/blacksheep/)

```console
pip install 'blacksheep[uvicorn]'
```

```python
from blacksheep import json, redirect, Application, Request
from p189client import P189Client

# TODO: 改成你自己的账户和密码，不写就是扫码登录
client = P189Client(username="", password="")
# 或者可以写死某个特定的 access_token
# client = P189Client(cookies="")
# client.access_token = ""

app = Application(show_error_details=__debug__)

@app.router.route("/{path:path}", methods=["GET", "HEAD"])
async def index(request: Request, path: str, id: int, family_id: int = 0):
    if family_id:
        payload = {"fileId": id, "familyId": family_id}
    else:
        payload = {"fileId": id}
    url = await client.download_url(payload, use_access_token=True, async_=True)
    return redirect(url)

if __name__ == "__main__":
    from uvicorn import run

    run(app, host="0.0.0.0", port=8189)
```

### 2. 签到和抽奖

```python
from p189client import P189Client

# TODO: 改成你自己的账户和密码，不写就是扫码登录
client = P189Client(username="", password="")

# 签到
print("签到", client.user_sign())

# 抽奖
from time import sleep
print("\n抽奖")
for i, task_id in enumerate(["TASK_SIGNIN", "TASK_SIGNIN_PHOTOS", "TASK_2022_FLDFS_KJ"]):
    if i:
        # NOTE: 休息 5 秒，防止被说过于频繁
        sleep(5)
    print(task_id, client.user_draw(task_id))
```

## 其它资源

- 如果你需要更详细的文档，特别是关于各种接口的信息，可以阅读

    [https://p189client.readthedocs.io/en/latest/](https://p189client.readthedocs.io/en/latest/)
