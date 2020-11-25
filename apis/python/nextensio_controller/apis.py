import sys
import requests
import time
import json


def is_controller_up(url):
    try:
        ret = requests.get(url+"getalltenants")
        return (ret.status_code == 200)
    except:
        pass
        return False


def create_gateway(url, gw):
    data = {'name': gw}
    try:
        ret = requests.post(url+"addgateway", json=data)
        if ret.status_code != 200 or ret.json()['Result'] != "ok":
            return False
        return True
    except:
        pass
        return False


def create_tenant(url, name, gws, domains, image, pods):
    data = {'curid': 'unknown', 'name': name, 'gateways': gws,
            'domains': domains, 'image': image, 'pods': pods}
    try:
        ret = requests.post(url+"addtenant", json=data)
        if ret.status_code != 200 or ret.json()['Result'] != "ok":
            return False
        return True
    except:
        pass
        return False


def get_tenants(url):
    try:
        ret = requests.get(url+"getalltenants")
        if ret.status_code != 200:
            return False, json.dumps([])
        return True, ret.json()
    except:
        pass
        return False, json.dumps([])


def create_user(url, uid, tenant, name, email, services, gateway, pod):
    data = {'uid': uid, 'tenant': tenant, 'name': name, 'email': email,
            'services': services, 'gateway': gateway, 'pod': pod}
    try:
        ret = requests.post(url+"adduser", json=data)
        if ret.status_code != 200 or ret.json()['Result'] != "ok":
            return False
        return True
    except:
        pass
        return False


def create_bundle(url, bid, tenant, name, services, gateway, pod):
    data = {'bid': bid, 'tenant': tenant, 'name': name,
            'services': services, 'gateway': gateway, 'pod': pod}
    try:
        ret = requests.post(url+"addbundle", json=data)
        if ret.status_code != 200 or ret.json()['Result'] != "ok":
            return False
        return True
    except:
        pass
        return False


def create_user_attr(url, uid, tenant, category, type, level, dept, team):
    data = {'uid': uid, 'tenant': tenant, 'category': category, 'type': type, 'level': level,
            'dept': dept, 'team': team}
    try:
        ret = requests.post(url+"adduserattr", json=data)
        if ret.status_code != 200 or ret.json()['Result'] != "ok":
            return False
        return True
    except:
        pass
        return False


def create_bundle_attr(url, bid, tenant, dept, team, IC, manager, nonemployee):
    data = {'bid': bid, 'tenant': tenant, 'IC': IC, 'manager': manager,
            'nonemployee': nonemployee, 'dept': dept, 'team': team}
    try:
        ret = requests.post(url+"addbundleattr", json=data)
        if ret.status_code != 200 or ret.json()['Result'] != "ok":
            return False
        return True
    except:
        pass
        return False


def create_policy(url, tenant, pid, policy):
    rego = []
    for p in policy:
        rego.append(ord(p))
    data = {'tenant': tenant, 'pid': pid, 'rego': rego}
    try:
        ret = requests.post(url+"addpolicy", json=data)
        if ret.status_code != 200 or ret.json()['Result'] != "ok":
            return False
        return True
    except:
        pass
        return False


def create_route(url, tenant, user, route, tag):
    data = {'tenant': tenant, 'route': user + ":" + route, 'tag': tag}
    try:
        ret = requests.post(url+"addroute", json=data)
        if ret.status_code != 200 or ret.json()['Result'] != "ok":
            return False
        return True
    except:
        pass
        return False


def create_cert(url, cert):
    data = {'certid': 'CACert', 'cert': [ord(c) for c in cert]}
    try:
        ret = requests.post(url+"addcert", json=data)
        if ret.status_code != 200 or ret.json()['Result'] != "ok":
            return False
        return True
    except:
        pass
        return False
