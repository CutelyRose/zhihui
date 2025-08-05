import requests
import json
from loguru import logger
import execjs
import time

session = requests.Session()
requests.packages.urllib3.disable_warnings()


# 通用 Headers
BASE_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                  '(KHTML, like Gecko) Chrome/122.0.6261.95 Safari/537.36',
    'Content-Type': 'application/json',
    'Accept': 'application/json, text/plain, */*',
    'Sdp-App-Id': 'e5649925-441d-4a53-b525-51a2f1c4e0a8',
    'referer': 'https://auth.smartedu.cn/',
}


def encrypt(name, c1, c2, c3):
    try:
        with open('1.js', encoding='utf-8') as f:
            jscode = f.read()
        return execjs.compile(jscode).call(name, c1, c2, c3)
    except Exception as e:
        logger.error(f"JS 加密失败: {e}")
        return ""


def get_captcha_code():
    url = '对接tx打码平台'
    payload = {
        'timeout': '60',
        'type': 'tencent-turing',
        'appid': '199128792',
        'token': '对接token',
        'developeraccount': '',
        'referer': 'https://auth.smartedu.cn/'
    }

    try:
        res = session.post(url, json=payload, headers=BASE_HEADERS, verify=False)
        logger.info(f"[验证码响应] {res.text}")
        return res.json()
    except Exception as e:
        logger.error(f"[验证码请求失败] {e}")
        return None


def get_session():
    device_id = encrypt('get_session', '', '', '')
    logger.info(f"device_id ---> {device_id}")

    payload = {'device_id': device_id}
    try:
        res = session.post(
            'https://uc-gateway.ykt.eduyun.cn/v1.1/sessions',
            headers=BASE_HEADERS,
            json=payload,
            verify=False
        )
        res_json = res.json()
        return device_id, res_json.get('session_id'), res_json.get('session_key')
    except Exception as e:
        logger.error(f"[获取 session 失败] {e}")
        return None, None, None


def validate_captcha(session_id, ticket, randstr):
    url = f'https://uc-gateway.ykt.eduyun.cn/v1.1/sessions/{session_id}/third_captcha_code/valid'
    payload = {
        'third_type': 1,
        'third_app_id': '199128792',
        'ticket': ticket,
        'rand_str': randstr
    }

    try:
        res = session.post(url, json=payload, headers=BASE_HEADERS, verify=False)
        return res.json().get('identify_code')
    except Exception as e:
        logger.error(f"[验证码校验失败] {e}")
        return None


def request_login_token(device_id, session_id, login_name, password, identify_code, zhitong_password):
    url = "https://sso.basic.smartedu.cn/v1.1/tokens"

    bodys_data = {
        "$headers": {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "SDP-APP-ID": "e5649925-441d-4a53-b525-51a2f1c4e0a8",
            "UC-COLL": f"e5649925-441d-4a53-b525-51a2f1c4e0a8/1.0(Win10;Chrome138;1707x960;{device_id};)",
            "Host": "sso.basic.smartedu.cn"
        },
        "$body": {
            "session_id": session_id,
            "login_name": login_name,
            "password": password,
            "identify_code": identify_code,
            "zhitong_password": zhitong_password
        },
        "$method": "post"
    }

    params = {
        "$proxy": "proxyhttp",
        "bodys": json.dumps(bodys_data),
        "callback": f"nd_uc_sdk_{int(time.time() * 1000)}0"
    }

    try:
        res = session.get(url, headers=BASE_HEADERS, params=params, verify=False)
        logger.info(f"[登录响应] {res.text}")
    except Exception as e:
        logger.error(f"[登录请求失败] {e}")


def login(username, password_plain):
    captcha_resp = get_captcha_code()
    if not captcha_resp or not captcha_resp.get('success'):
        logger.error("验证码获取失败")
        return

    device_id, session_id, session_key = get_session()
    if not session_id or not session_key:
        logger.error("Session 获取失败")
        return

    ticket = json.loads(captcha_resp['data']['code'])['ticket']
    randstr = json.loads(captcha_resp['data']['code'])['randstr']

    identify_code = validate_captcha(session_id, ticket, randstr)
    if not identify_code:
        logger.error("验证码校验失败")
        return

    # 加密用户信息
    login_name = encrypt('DES_Encrypt', username, session_key, '0')
    password = encrypt('DES_Encrypt', password_plain, session_key, "£¬¡£fdjf,jkgfkl")
    zhitong_password = encrypt('DES_Encrypt', password_plain, session_key, '')

    logger.info(f"login_name ---> {login_name}")
    logger.info(f"password ---> {password}")
    logger.info(f"zhitong_password ---> {zhitong_password}")

    request_login_token(device_id, session_id, login_name, password, identify_code, zhitong_password)


if __name__ == '__main__':
    login('账号', '密码')
