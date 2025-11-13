# -*- coding: utf8 -*-
import math
import traceback
from datetime import datetime
import pytz
import uuid
import argparse
import getpass

import json
import random
import re
import time
import os

import requests
from util.aes_help import  encrypt_data, decrypt_data
import util.zepp_helper as zeppHelper

# 获取默认值转int
def get_int_value_default(_config: dict, _key, default):
    _config.setdefault(_key, default)
    return int(_config.get(_key))


# 获取当前时间对应的最大和最小步数
def get_min_max_by_time(hour=None, minute=None):
    if hour is None:
        hour = time_bj.hour
    if minute is None:
        minute = time_bj.minute
    time_rate = min((hour * 60 + minute) / (22 * 60), 1)
    min_step = get_int_value_default(config, 'MIN_STEP', 18000)
    max_step = get_int_value_default(config, 'MAX_STEP', 25000)
    return int(time_rate * min_step), int(time_rate * max_step)


# 虚拟ip地址
def fake_ip():
    # 随便找的国内IP段：223.64.0.0 - 223.117.255.255
    return f"{223}.{random.randint(64, 117)}.{random.randint(0, 255)}.{random.randint(0, 255)}"


# 账号脱敏
def desensitize_user_name(user):
    if len(user) <= 8:
        ln = max(math.floor(len(user) / 3), 1)
        return f'{user[:ln]}***{user[-ln:]}'
    return f'{user[:3]}****{user[-4:]}'


# 获取北京时间
def get_beijing_time():
    target_timezone = pytz.timezone('Asia/Shanghai')
    # 获取当前时间
    return datetime.now().astimezone(target_timezone)


# 格式化时间
def format_now():
    return get_beijing_time().strftime("%Y-%m-%d %H:%M:%S")


# 获取时间戳
def get_time():
    current_time = get_beijing_time()
    return "%.0f" % (current_time.timestamp() * 1000)


# 获取登录code
def get_access_token(location):
    code_pattern = re.compile("(?<=access=).*?(?=&)")
    result = code_pattern.findall(location)
    if result is None or len(result) == 0:
        return None
    return result[0]


def get_error_code(location):
    code_pattern = re.compile("(?<=error=).*?(?=&)")
    result = code_pattern.findall(location)
    if result is None or len(result) == 0:
        return None
    return result[0]


# pushplus消息推送
def push_plus(title, content):
    requestUrl = f"http://www.pushplus.plus/send"
    data = {
        "token": PUSH_PLUS_TOKEN,
        "title": title,
        "content": content,
        "template": "html",
        "channel": "wechat"
    }
    try:
        response = requests.post(requestUrl, data=data)
        if response.status_code == 200:
            json_res = response.json()
            print(f"pushplus推送完毕：{json_res['code']}-{json_res['msg']}")
        else:
            print("pushplus推送失败")
    except:
        print("pushplus推送异常")


class MiMotionRunner:
    def __init__(self, _user, _passwd, _user_tokens=None):
        self.user_id = None
        self.device_id = str(uuid.uuid4())
        user = str(_user)
        password = str(_passwd)
        self.invalid = False
        self.log_str = ""
        self.user_tokens = _user_tokens if _user_tokens is not None else {}
        if user == '' or password == '':
            self.error = "用户名或密码填写有误！"
            self.invalid = True
            pass
        self.password = password
        if (user.startswith("+86")) or "@" in user:
            user = user
        else:
            user = "+86" + user
        if user.startswith("+86"):
            self.is_phone = True
        else:
            self.is_phone = False
        self.user = user
        # self.fake_ip_addr = fake_ip()
        # self.log_str += f"创建虚拟ip地址：{self.fake_ip_addr}\n"

    # 检查token是否过期（基于时间，避免每次都调用API）
    def _is_token_expired(self, token_time_str, expire_hours=24):
        """检查token是否过期
        expire_hours: token有效期（小时），app_token默认24小时，login_token默认7天，access_token默认30天
        """
        if token_time_str is None:
            return True
        try:
            token_time = int(token_time_str)
            current_time = int(get_time())
            # 时间戳是毫秒，转换为小时
            elapsed_hours = (current_time - token_time) / (1000 * 60 * 60)
            return elapsed_hours >= expire_hours
        except:
            return True

    # 登录
    def login(self, skip_token_check=False):
        """
        skip_token_check: 如果为True，跳过API验证，仅基于时间判断token是否过期
        """
        user_token_info = self.user_tokens.get(self.user)
        if user_token_info is not None:
            access_token = user_token_info.get("access_token")
            login_token = user_token_info.get("login_token")
            app_token = user_token_info.get("app_token")
            self.device_id = user_token_info.get("device_id")
            self.user_id = user_token_info.get("user_id")
            if self.device_id is None:
                self.device_id = str(uuid.uuid4())
                user_token_info["device_id"] = self.device_id
            
            # 先基于时间判断token是否过期（避免每次都调用API）
            app_token_time = user_token_info.get("app_token_time")
            if not self._is_token_expired(app_token_time, expire_hours=24):
                # app_token在24小时内，认为有效，直接使用
                self.log_str += f"使用缓存的app_token（距获取时间：{int((int(get_time()) - int(app_token_time)) / (1000 * 60 * 60))}小时）\n"
                return app_token
            
            # app_token可能过期，需要验证或刷新
            if skip_token_check:
                # 跳过API验证，直接尝试刷新
                self.log_str += "app_token可能已过期，尝试刷新\n"
            else:
                # 调用API验证token是否真的有效
                ok, msg = zeppHelper.check_app_token(app_token)
                if ok:
                    # token仍然有效，更新时间戳
                    user_token_info["app_token_time"] = get_time()
                    self.log_str += "app_token验证有效，更新时间戳\n"
                    return app_token
                else:
                    self.log_str += f"app_token失效 重新获取 last grant time: {app_token_time}\n"
            
            # app_token失效，尝试用login_token刷新
            login_token_time = user_token_info.get("login_token_time")
            if not self._is_token_expired(login_token_time, expire_hours=7*24):
                # login_token在7天内，尝试刷新app_token
                app_token, msg = zeppHelper.grant_app_token(login_token)
                if app_token is not None:
                    self.log_str += "使用login_token刷新app_token成功\n"
                    user_token_info["app_token"] = app_token
                    user_token_info["app_token_time"] = get_time()
                    return app_token
            
            # login_token也失效或无法刷新，尝试用access_token重新获取
            access_token_time = user_token_info.get("access_token_time")
            if not self._is_token_expired(access_token_time, expire_hours=30*24):
                # access_token在30天内，尝试重新获取login_token和app_token
                self.log_str += f"login_token失效或无法刷新，使用access_token重新获取 last grant time: {login_token_time}\n"
                login_token, app_token, user_id, msg = zeppHelper.grant_login_tokens(access_token, self.device_id, self.is_phone)
                if login_token is not None:
                    user_token_info["login_token"] = login_token
                    user_token_info["app_token"] = app_token
                    user_token_info["user_id"] = user_id
                    user_token_info["login_token_time"] = get_time()
                    user_token_info["app_token_time"] = get_time()
                    self.user_id = user_id
                    self.log_str += "使用access_token重新获取login_token和app_token成功\n"
                    return app_token
                else:
                    self.log_str += f"access_token已失效：{msg} last grant time:{access_token_time}\n"
            else:
                self.log_str += f"access_token已过期（距获取时间：{int((int(get_time()) - int(access_token_time)) / (1000 * 60 * 60))}小时）\n"

        # access_token 失效 或者没有保存加密数据
        access_token, msg = zeppHelper.login_access_token(self.user, self.password)
        if access_token is None:
            self.log_str += "登录获取accessToken失败：%s" % msg
            return None
        # print(f"device_id:{self.device_id} isPhone: {self.is_phone}")
        login_token, app_token, user_id, msg = zeppHelper.grant_login_tokens(access_token, self.device_id, self.is_phone)
        if login_token is None:
            self.log_str += f"登录提取的 access_token 无效：{msg}"
            return None

        user_token_info = dict()
        user_token_info["access_token"] = access_token
        user_token_info["login_token"] = login_token
        user_token_info["app_token"] = app_token
        user_token_info["user_id"] = user_id
        # 记录token获取时间
        user_token_info["access_token_time"] = get_time()
        user_token_info["login_token_time"] = get_time()
        user_token_info["app_token_time"] = get_time()
        if self.device_id is None:
            self.device_id = uuid.uuid4()
        user_token_info["device_id"] = self.device_id
        self.user_tokens[self.user] = user_token_info
        return app_token


    # 主函数
    def login_and_post_step(self, step_value=None, min_step=None, max_step=None, skip_token_check=False):
        if self.invalid:
            return "账号或密码配置有误", False
        app_token = self.login(skip_token_check=skip_token_check)
        if app_token is None:
            return "登陆失败！", False

        if step_value is not None:
            # 使用指定的步数
            step = str(step_value)
            self.log_str += f"已设置为指定步数:{step}\n"
        else:
            # 使用随机步数
            step = str(random.randint(min_step, max_step))
            self.log_str += f"已设置为随机步数范围({min_step}~{max_step}) 随机值:{step}\n"
        ok, msg = zeppHelper.post_fake_brand_data(step, app_token, self.user_id)
        return f"修改步数（{step}）[" + msg + "]", ok


# 启动主函数
def push_to_push_plus(exec_results, summary):
    # 判断是否需要pushplus推送
    if PUSH_PLUS_TOKEN is not None and PUSH_PLUS_TOKEN != '' and PUSH_PLUS_TOKEN != 'NO':
        if PUSH_PLUS_HOUR is not None and PUSH_PLUS_HOUR.isdigit():
            if time_bj.hour != int(PUSH_PLUS_HOUR):
                print(f"当前设置push_plus推送整点为：{PUSH_PLUS_HOUR}, 当前整点为：{time_bj.hour}，跳过推送")
                return
        html = f'<div>{summary}</div>'
        if len(exec_results) >= PUSH_PLUS_MAX:
            html += '<div>账号数量过多，详细情况请前往github actions中查看</div>'
        else:
            html += '<ul>'
            for exec_result in exec_results:
                success = exec_result['success']
                if success is not None and success is True:
                    html += f'<li><span>账号：{exec_result["user"]}</span>刷步数成功，接口返回：{exec_result["msg"]}</li>'
                else:
                    html += f'<li><span>账号：{exec_result["user"]}</span>刷步数失败，失败原因：{exec_result["msg"]}</li>'
            html += '</ul>'
        push_plus(f"{format_now()} 刷步数通知", html)


def run_single_account(total, idx, user_mi, passwd_mi, user_tokens=None, step_value=None, min_step=None, max_step=None, skip_token_check=False):
    idx_info = ""
    if idx is not None:
        idx_info = f"[{idx + 1}/{total}]"
    log_str = f"[{format_now()}]\n{idx_info}账号：{desensitize_user_name(user_mi)}\n"
    try:
        runner = MiMotionRunner(user_mi, passwd_mi, user_tokens)
        exec_msg, success = runner.login_and_post_step(step_value, min_step, max_step, skip_token_check)
        log_str += runner.log_str
        log_str += f'{exec_msg}\n'
        exec_result = {"user": user_mi, "success": success,
                       "msg": exec_msg}
    except:
        log_str += f"执行异常:{traceback.format_exc()}\n"
        log_str += traceback.format_exc()
        exec_result = {"user": user_mi, "success": False,
                       "msg": f"执行异常:{traceback.format_exc()}"}
    print(log_str)
    return exec_result


def execute(encrypt_support=False, user_tokens_dict=None, aes_key=None, step_value=None, min_step=None, max_step=None, skip_token_check=False):
    if user_tokens_dict is None:
        user_tokens_dict = {}
    user_list = users.split('#')
    passwd_list = passwords.split('#')
    exec_results = []
    if len(user_list) == len(passwd_list):
        idx, total = 0, len(user_list)
        if use_concurrent:
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as executor:
                exec_results = executor.map(lambda x: run_single_account(total, x[0], *x[1], user_tokens_dict, step_value, min_step, max_step, skip_token_check),
                                            enumerate(zip(user_list, passwd_list)))
        else:
            for user_mi, passwd_mi in zip(user_list, passwd_list):
                exec_results.append(run_single_account(total, idx, user_mi, passwd_mi, user_tokens_dict, step_value, min_step, max_step, skip_token_check))
                idx += 1
                if idx < total:
                    # 每个账号之间间隔一定时间请求一次，避免接口请求过于频繁导致异常
                    time.sleep(sleep_seconds)
        if encrypt_support and user_tokens_dict is not None and aes_key is not None:
            persist_user_tokens(user_tokens_dict, aes_key)
        success_count = 0
        push_results = []
        for result in exec_results:
            push_results.append(result)
            if result['success'] is True:
                success_count += 1
        summary = f"\n执行账号总数{total}，成功：{success_count}，失败：{total - success_count}"
        print(summary)
        push_to_push_plus(push_results, summary)
    else:
        print(f"账号数长度[{len(user_list)}]和密码数长度[{len(passwd_list)}]不匹配，跳过执行")
        exit(1)


def prepare_user_tokens(aes_key) -> dict:
    data_path = r"encrypted_tokens.data"
    if os.path.exists(data_path):
        with open(data_path, 'rb') as f:
            data = f.read()
        try:
            decrypted_data = decrypt_data(data, aes_key, None)
            # 假设原始明文为 UTF-8 编码文本
            return json.loads(decrypted_data.decode('utf-8', errors='strict'))
        except:
            print("密钥不正确或者加密内容损坏 放弃token")
            return dict()
    else:
        return dict()

def persist_user_tokens(user_tokens, aes_key):
    data_path = r"encrypted_tokens.data"
    origin_str = json.dumps(user_tokens, ensure_ascii=False)
    cipher_data = encrypt_data(origin_str.encode("utf-8"), aes_key, None)
    with open(data_path, 'wb') as f:
        f.write(cipher_data)
        f.flush()
        f.close()

if __name__ == "__main__":
    # 北京时间
    time_bj = get_beijing_time()
    encrypt_support = False
    user_tokens = dict()
    
    # 解析命令行参数
    parser = argparse.ArgumentParser(description='小米运动自动刷步数工具')
    parser.add_argument('--user', '-u', type=str, help='登录账号（手机号或邮箱），多账号用#分隔')
    parser.add_argument('--password', '-p', type=str, help='登录密码，多账号用#分隔')
    parser.add_argument('--step', type=int, help='指定步数（如果设置此参数，将使用指定步数，不再随机）')
    parser.add_argument('--min-step', type=int, default=18000, help='最小步数（默认：18000，仅在未指定--step时有效）')
    parser.add_argument('--max-step', type=int, default=25000, help='最大步数（默认：25000，仅在未指定--step时有效）')
    parser.add_argument('--aes-key', type=str, help='AES加密密钥（16个字符），用于保存token')
    parser.add_argument('--push-plus-token', type=str, default='', help='PushPlus推送token（可选）')
    parser.add_argument('--sleep-gap', type=float, default=5, help='多账号执行间隔秒数（默认：5）')
    parser.add_argument('--interactive', '-i', action='store_true', help='交互式输入账号密码')
    parser.add_argument('--skip-token-check', action='store_true', help='跳过token API验证，仅基于时间判断（更快，但可能使用已失效的token）')
    
    args = parser.parse_args()
    
    # 处理AES_KEY
    if os.environ.__contains__("AES_KEY") is True:
        aes_key = os.environ.get("AES_KEY")
    elif args.aes_key:
        aes_key = args.aes_key
    else:
        aes_key = None
    
    if aes_key is not None:
        aes_key = aes_key.encode('utf-8')
        if len(aes_key) == 16:
            encrypt_support = True
            user_tokens = prepare_user_tokens(aes_key)
        else:
            print("AES_KEY长度必须为16个字符，无法使用加密保存功能")
            aes_key = None
    else:
        print("AES_KEY未设置，token将不会保存到本地")
    
    # 获取配置：优先从环境变量，其次从命令行参数，最后交互式输入
    config = dict()
    
    if os.environ.__contains__("CONFIG"):
        # 从环境变量读取（GitHub Actions模式）
        try:
            config = dict(json.loads(os.environ.get("CONFIG")))
        except:
            print("CONFIG格式不正确，请检查Secret配置，请严格按照JSON格式：使用双引号包裹字段和值，逗号不能多也不能少")
            traceback.print_exc()
            exit(1)
    else:
        # 本地运行模式：从命令行参数或交互式输入
        if args.interactive or (not args.user or not args.password):
            # 交互式输入
            print("=" * 50)
            print("小米运动自动刷步数工具 - 本地运行模式")
            print("=" * 50)
            if not args.user:
                users = input("请输入账号（手机号或邮箱，多账号用#分隔）: ").strip()
            else:
                users = args.user
            if not args.password:
                passwords = getpass.getpass("请输入密码（多账号用#分隔）: ").strip()
            else:
                passwords = args.password
            # 交互式输入步数
            if args.step is None:
                step_input = input("请输入步数（直接回车使用随机步数）: ").strip()
                if step_input:
                    try:
                        step_value = int(step_input)
                    except ValueError:
                        print("步数格式不正确，将使用随机步数")
                        step_value = None
                else:
                    step_value = None
            else:
                step_value = args.step
        else:
            # 从命令行参数读取
            users = args.user
            passwords = args.password
            step_value = args.step
        
        # 构建配置字典
        config = {
            'USER': users,
            'PWD': passwords,
            'STEP': str(step_value) if step_value is not None else '',
            'MIN_STEP': str(args.min_step),
            'MAX_STEP': str(args.max_step),
            'PUSH_PLUS_TOKEN': args.push_plus_token if args.push_plus_token else '',
            'PUSH_PLUS_HOUR': '',
            'PUSH_PLUS_MAX': '30',
            'SLEEP_GAP': str(args.sleep_gap),
            'USE_CONCURRENT': 'False'
        }
    
    # 初始化参数
    PUSH_PLUS_TOKEN = config.get('PUSH_PLUS_TOKEN')
    PUSH_PLUS_HOUR = config.get('PUSH_PLUS_HOUR')
    PUSH_PLUS_MAX = get_int_value_default(config, 'PUSH_PLUS_MAX', 30)
    sleep_seconds = config.get('SLEEP_GAP')
    if sleep_seconds is None or sleep_seconds == '':
        sleep_seconds = 5
    sleep_seconds = float(sleep_seconds)
    users = config.get('USER')
    passwords = config.get('PWD')
    if users is None or passwords is None:
        print("未正确配置账号密码，无法执行")
        exit(1)
    
    # 处理步数设置
    step_value = config.get('STEP')
    if step_value and step_value != '':
        try:
            step_value = int(step_value)
            print(f"使用指定步数：{step_value}")
        except ValueError:
            step_value = None
            print("步数格式不正确，将使用随机步数")
    else:
        step_value = None
    
    if step_value is None:
        # 判断是否从环境变量读取（GitHub Actions模式）
        if os.environ.__contains__("CONFIG"):
            # GitHub Actions模式：直接使用配置的MIN_STEP和MAX_STEP，不根据时间计算
            min_step = get_int_value_default(config, 'MIN_STEP', 18000)
            max_step = get_int_value_default(config, 'MAX_STEP', 25000)
            print(f"GitHub Actions模式：使用配置的随机步数范围：{min_step} ~ {max_step}")
        else:
            # 本地模式：根据时间计算步数范围
            min_step, max_step = get_min_max_by_time()
            print(f"本地模式：使用时间计算的随机步数范围：{min_step} ~ {max_step}")
    else:
        min_step = None
        max_step = None
    
    use_concurrent = config.get('USE_CONCURRENT')
    if use_concurrent is not None and use_concurrent == 'True':
        use_concurrent = True
    else:
        print(f"多账号执行间隔：{sleep_seconds}秒")
        use_concurrent = False
    
    # 处理skip_token_check参数
    if os.environ.__contains__("CONFIG"):
        # 环境变量模式，从config中读取
        skip_token_check = config.get('SKIP_TOKEN_CHECK', '').lower() == 'true'
    else:
        # 命令行模式
        skip_token_check = args.skip_token_check if hasattr(args, 'skip_token_check') else False
    
    if skip_token_check:
        print("已启用快速模式：跳过token API验证，仅基于时间判断")
    
    # 执行
    execute(encrypt_support, user_tokens, aes_key, step_value, min_step, max_step, skip_token_check)
