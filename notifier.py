"""
通知模块 - Telegram 和 Webhook 通知
"""
import html
import json
import requests

# 超时设置
REQUEST_TIMEOUT = 15


def _scrub(text, secrets=()):
    """把错误信息里的敏感值（如 bot token）替换掉，避免回显/落盘泄漏。"""
    result = str(text)
    for secret in secrets:
        if secret:
            result = result.replace(str(secret), '***')
    return result


def send_telegram(token, chat_id, message):
    """发送 Telegram 消息"""
    if not token or not chat_id:
        return False, "Token 或 chat_id 为空"

    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {
        'chat_id': chat_id,
        # HTML 模式下消息里的 <, >, & 未转义会让 Telegram 返回 400 导致通知静默丢失
        'text': html.escape(str(message)),
        'parse_mode': 'HTML'
    }

    try:
        resp = requests.post(url, json=payload, timeout=REQUEST_TIMEOUT)
        data = resp.json()
        if resp.status_code == 200 and data.get('ok'):
            return True, f"发送成功 (msg_id={data['result']['message_id']})"
        else:
            return False, _scrub(f"发送失败: {data.get('description', resp.text)}", [token])
    except Exception as e:
        # requests 的异常文本里含完整 URL，URL 里就是 token —— 必须脱敏后再返回/打印
        return False, _scrub(f"请求异常: {e.__class__.__name__}", [token])


def send_webhook(config, message):
    """发送 Webhook 通知"""
    url = config.get('url', '')
    if not url:
        return False, "Webhook URL 为空"

    content_type = config.get('content_type', 'application/json')
    headers = dict(config.get('headers', {}))
    body_template = config.get('body_template', '{"msg": "{{message}}"}')

    # 替换模板变量
    body = body_template.replace('{{message}}', message)

    try:
        if content_type == 'application/json':
            headers['Content-Type'] = 'application/json'
            # body 已经是 JSON 字符串，尝试解析后再发送
            try:
                body_json = json.loads(body)
            except json.JSONDecodeError:
                body_json = body
            resp = requests.post(url, json=body_json, headers=headers, timeout=REQUEST_TIMEOUT)
        else:
            headers['Content-Type'] = content_type
            resp = requests.post(url, data=body.encode('utf-8'), headers=headers, timeout=REQUEST_TIMEOUT)

        if 200 <= resp.status_code < 300:
            return True, f"发送成功 (status={resp.status_code})"
        else:
            return False, f"发送失败 (status={resp.status_code}): {resp.text[:200]}"
    except Exception as e:
        secrets = [v for k, v in headers.items() if 'secret' in k.lower() or 'token' in k.lower()]
        return False, _scrub(f"请求异常: {e.__class__.__name__}", secrets)
