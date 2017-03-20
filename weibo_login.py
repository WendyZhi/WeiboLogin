#!/usr/bin/python
# -*- coding: utf-8 -*-
import urllib
import base64
import binascii
import rsa
import requests
import re
import json

class WeiboLogin:
    def __init__(self, username, password):
        self.username = username
        self.password = password

    def login(self):
        # encode username
        su = base64.b64encode(urllib.quote(self.username).encode(encoding="utf-8"))

        session = requests.Session()

        # prelogin
        prelogin_url = 'http://login.sina.com.cn/sso/prelogin.php?entry=weibo&callback=sinaSSOController.preloginCallBack&su=%s&rsakt=mod&checkpin=1&client=ssologin.js(v1.4.18)&_=1489906045014' % urllib.quote(su)
        prelogin_response = session.get(prelogin_url)
        data = re.findall(r'(?<=\().*(?=\))', prelogin_response.text)[0]
        data = json.loads(data)

        # prepare post data
        public_key = data['pubkey']
        public_key = int(public_key, 16)
        public_key = rsa.PublicKey(public_key, 65537)
        message = str(data['servertime']) + "\t" + str(data['nonce']) + "\n" + str(self.password)
        sp = binascii.b2a_hex(rsa.encrypt(message.encode(encoding="utf-8"), public_key))
        post_data = {
            'entry': "weibo",
            "gateway": "1",
            "from": "",
            "savestate": "7",
            "pagereferer": "http://login.sina.com.cn/sso/logout.php?entry=miniblog&r=http%3A%2F%2Fweibo.com%2Flogout.php%3Fbackurl%3D%252Fhttp://login.sina.com.cn/sso/logout.php?entry=miniblog&r=http%3A%2F%2Fweibo.com%2Flogout.php%3Fbackurl%3D%252F",
            "userticket": "1",
            "vsnf": "1",
            "su": su,
            "service": "miniblog",
            "servertime": data['servertime'],
            "nonce": data['nonce'],
            "pwencode": "rsa2",
            "sp": sp,
            "prelt": "60",
            "sr": "1920*1080",
            "encoding": "UTF-8",
            "url": 'http://weibo.com/ajaxlogin.php?framelogin=1&callback=parent.sinaSSOController.feedBackUrlCallBack',
            "returntype": "META",
            "rsakv": data['rsakv'],
            }

        # post data to login
        login_url = 'http://login.sina.com.cn/sso/login.php?client=ssologin.js(v1.4.18)'
        login_response = session.post(login_url, data=post_data)
        login_html = login_response.content.decode(encoding="GBK")

        # find redirect url
        pattern = re.compile('location\.replace\(\'(.*?)\'\)')
        redirect_url = pattern.search(login_html).group(1)

        # redirect to the url
        redirect_response = session.get(redirect_url)
        redirect_html = redirect_response.content.decode(encoding="GBK")

        # find userdomain
        pattern = re.compile(r'"userdomain":"(.*?)"')
        redirect_url = 'http://weibo.com/' + pattern.search(redirect_html).group(1)
        redirect_response = session.get(login_url)
        
        return session

if __name__ == '__main__':
    weibo = WeiboLogin("username", "password")
    session = weibo.login()
    response = session.get("http://weibo.com/u/1283716724")
    print response.content.decode(encoding="utf-8")
