# -*- coding: utf-8 -*-
#!/usr/bin/env python3
__ver__ = ''
__author__ = 'geyeg'

from datetime import datetime
from datetime import timedelta
import time
import json
import struct
import re
import binascii
from ws_vars import *


'''
取字典值，无则返回 ''
'''
def get_dict_val(key, dictionary):
    if key in dictionary:
        return dictionary[key]
    else:
        return ''


def now(fmt=''):
    if fmt == 'time_stamp':
        return (datetime.utcnow() + timedelta(hours=timezone)).strftime('%Y%m%d%H%M%S')
    elif fmt == 'time_stamp_ms':
        return (datetime.utcnow() + timedelta(hours=timezone)).strftime('%Y%m%d%H%M%S%f')
    else:
        return (datetime.utcnow() + timedelta(hours=timezone)).strftime('%Y-%m-%d %H:%M:%S')


'''
检验接收到的时间格式是否正确
'''
def verify_time(str_datetime, output_format='normal'):
    if output_format == 'normal':
        try:
            t = time.mktime(time.strptime(str_datetime, '%Y%m%d%H%M%S'))
            result = str(datetime.fromtimestamp(t))
        except ValueError as e:
            result = '1970-01-01 12:12:12'
            logging.error('[{}] datetime format error.'.format(str_datetime))
    else:
        try:
            t = time.strptime(str_datetime, '%Y-%m-%d %H:%M:%S')
            result = time.strftime('%Y%m%d%H%M%S', t)
        except ValueError as e:
            result = '1970-01-01 12:12:12'
            logging.error('[{}] datetime format error.'.format(str_datetime))
    return result

'''
时间格式转换
'''
def time_format(str_datetime, fmt=''):
    pass

'''
char_checksum 按字节计算校验和。每个字节被翻译为无符号整数
@param data: 字节串
@param byteorder: 大/小端
'''
def uchar_checksum(data, byteorder='little'):
    length = len(data)
    _checksum = 0
    for i in range(0, length):
        _checksum += int.from_bytes(data[i:i + 1], byteorder, signed=False)
        _checksum &= 0xFF  # 强制截断
    return _checksum


"""
char_checksum 按字节计算校验和。每个字节被翻译为带符号整数
@param data: 字节串
@param byteorder: 大/小端
"""
def char_checksum(data, byteorder='little'):
    length = len(data)
    _checksum = 0
    for i in range(0, length):
        x = int.from_bytes(data[i:i + 1], byteorder, signed=True)
        if x > 0 and _checksum > 0:
            _checksum += x
            if _checksum > 0x7F:  # 上溢出
                _checksum = (_checksum & 0x7F) - 0x80  # 取补码就是对应的负数值
        elif x < 0 and _checksum < 0:
            _checksum += x
            if _checksum < -0x80:  # 下溢出
                _checksum &= 0x7F
        else:
            _checksum += x  # 正负相加，不会溢出
            # print(checksum)

    return _checksum


def checksum(byte_data):
    checksum_value = 0
    for byte in byte_data:
        checksum_value += byte  # int.from_bytes(byte, byteorder='little', signed=False)
        checksum_value &= 0xFF
    return checksum_value


'''
消息校验是否通过
'''
def is_checksum_pass(msg):
    _checksum = 0
    checksum_value = struct.unpack('<B', msg[-2:-1])[0]
    msg_body = msg[6:-2]
    for byte in msg_body:
        _checksum += byte  # int.from_bytes(byte, byteorder='little', signed=False)
        _checksum &= 0xFF
    if checksum_value == _checksum:
        return True
    else:
        return False


'''
从给出的字节流截取长度,返回整型
每帧接收的字符数为用户数据长度Length+8
'''
def get_length(msg):
    length, length_verify = struct.unpack('<HH', msg[1:5])
    if length == length_verify:
        return length
    else:
        return -1


'''
post数据到api服务器
数据格式：json
'''
def http_post(uri='', post_data=[], post_retry_times=3):
    for i in range(post_retry_times):
        try:
            req = requests.post(uri, json.dumps(post_data), headers=headers)
        except Exception as e:
            logging.error(e)
        else:
            if req.status_code == requests.codes.ok:
                #post 成功就退出
                logging.info('Post succeed:[{}]{}'.format(str(req.status_code), json.dumps(post_data)))
                break
            else:
                logging.error('Post {} failure at {},[{}]:{}'.format(uri, now(), str(req.status_code),
                              json.dumps(post_data)))
            return req.status_code
        time.sleep(POST_RETRY_INTERVAL)
    return ''


def http_get(uri='/command_data'):
    try:
        response = requests.get(API_BASE_URL + uri, headers=headers, params={'ip:': ip, 'port': port})
    except Exception as e:
        logging.error(e)
    else:
        if response.text:
            return json.loads(response.text)
    return ''


'''
b'\x68\x09\x08\x09\x08\x68\x70\x04\x12\x67\x01\x00\x98\x7F\x00\x00\x10\x00\x3B\x5F\x63\x69'
转成
'68 09 08 09 08 68 70 04 12 ...'
'''
def bytes_to_str_num(in_bytes=b''):
    return ' '.join([_hex[2:].zfill(2) for _hex in list(map(hex, in_bytes))])


'''
集中器或水表号按地址格式整理，例如下：
'C0070007' ->> {0xC0,0x07,0x00,0x07}
'''
def format_address(me_number):
    kk = re.findall(r'.{2}', me_number)
    ak = '{0x'
    mk = ak + ',0x'.join(kk)
    ok = mk + '}'
    return ok


'''
字节流转BCD字符串
输入：\x20\x28\x66
输出：202866
输出（reverse）：662820   两位为一组，整串反转
'''
def bytes_to_bcd_str(bytes_str=b'', reverse=''):
    bcd_str = ''.join(list(map(lambda x: hex_letters[x >> 4] + hex_letters[x & 0b00001111], bytes_str)))
    if reverse == 'reverse':
        bcd_str = ''.join(re.findall(r'.{2}', bcd_str)[::-1])
    return bcd_str


'''
16进制转为可显示的16进制字符串（每字两位一字节），以空格分隔，
b'\x68\x49\x00\x68' ->> 68 49 00 68
'''
def bytes_to_show(in_bytes=b''):
    # show_bytes = ' '.join(re.findall(r'.{2}', str(binascii.b2a_hex(in_bytes)).upper()))
    show_bytes = ' '.join(re.findall(r'.{2}', str(binascii.hexlify(in_bytes)).upper()[2:]))
    return show_bytes


'''
字符串转字节流BCD码
'''
def str_bcd_to_bytes(bcd_str='', reverse=''):
    # bcd_str_list = re.findall(r'.{2}', bcd_str)
    # bcd_int_list = list(map(lambda x: int(x[0]) << 4 | int(x[1]), bcd_str_list))
    # bcd = struct.pack('>{0}B'.format(str(len(bcd_int_list))), *bcd_int_list)
    # bcd_bytes = bytearray.fromhex(bcd_str)
    if reverse == 'reverse':
        bcd_bytes = bytes.fromhex(reverse_bcd(bcd_str))
    else:
        bcd_bytes = bytes.fromhex(bcd_str)
    return bcd_bytes


'''
解出含有星期的日期时间
输入格式：21 05 14 03 06 18  月份转为二进制第5位为月份10位，D0~D4为月分个位，D6为星期
输出格式：20180603140521
'''
def convert_datetime_gdw_to_hy(gdw_datetime=b''):
    gdw_datetime_str = bytes_to_bcd_str(gdw_datetime[::-1])
    month_and_week = gdw_datetime[-2]
    # 月份中D0~D3为月份个位D5为月份10位，其它可以去掉（星期）
    month_low = month_and_week & 0b00001111
    month_high = month_and_week & 0b00010000 >> 5
    month_str = str(month_high) + str(month_low)
    hy_datetime = gdw_datetime_str[0:2] + month_str + gdw_datetime_str[4:]
    return '20' + hy_datetime


'''
把time_stamp_server格式转为gdw格式
'''
def convert_datetime_hy_to_gdw(time_stamp_server=''):
    # week = datetime.fromtimestamp(time.mktime(time.strptime(time_stamp_server, '%Y%m%d%H%M%S'))).weekday() + 1
    # 先去掉年份开头两位，再按每两位转成列表，然后反序，再合并
    rtm = ''.join(re.findall(r'.{2}', time_stamp_server[2:])[::-1])
    # month_str = rtm[-4:-2]
    # month_and_week_str = str((week << 1) | int(month_str[0])) + month_str[1]
    # month_and_week_str = str((week << 1) | int(month_str[0])) + month_str[1]
    # return rtm[0:8] + month_and_week_str + rtm[-2:]
    return rtm


def convert_to_int(in_val, error_value=0):
    try:
        _result = int(in_val)
    except ValueError as e:
        _result = error_value
    return _result


# 名称有待修改
def convert_to_int_90ef(in_val, error_value=141414141414.14):
    try:
        _result = int(in_val) / 100
    except ValueError as e:
        _result = error_value
    return _result


'''
'18060812'  ==>>  '18-06-08:12'
'''
def format_90ef_datetime(in_str=''):
    if len(in_str) == 8:
        _result = in_str[0:2] + '-' + in_str[2:4] + '-' + in_str[4:6] + ' ' + in_str[6:] + ':00'
    else:
        _result = in_str
    return _result


'''
把有需要的指令切割成项目数更小的指令，每个都是独立的
'''
def cmd_cutter(server_cmd=dict()):
    server_cmd_result = list()
    if server_cmd['feature'] == 'set_doc':
        # 把body拆分成5项一个列表
        body_list_per10item = [server_cmd['body'][i:i + 10] for i in range(0, len(server_cmd['body']), 10)]
        for body_item in body_list_per10item:  # 按每项（6个字典）组合成一个新指令
            cmd_set_doc = dict()
            cmd_set_doc['id'] = server_cmd['id']
            cmd_set_doc['concentrator_number'] = server_cmd['concentrator_number']
            cmd_set_doc['meter_number'] = server_cmd['meter_number']
            cmd_set_doc['feature'] = server_cmd['feature']
            cmd_set_doc['category'] = server_cmd['category']
            cmd_set_doc['_c'] = server_cmd['_c']
            cmd_set_doc['body'] = body_item
            server_cmd_result.append(cmd_set_doc)
    else:
        server_cmd_result.append(server_cmd)
    return server_cmd_result


def reset_send_status(concentrator=''):
    with lock:
        if concentrator in online_dev:
            online_dev[concentrator]['reply_cmd'] = ''
            online_dev[concentrator]['is_catch_reply'] = False
            online_dev[concentrator]['reply_cmd_afn'] = ''
            online_dev[concentrator]['is_sending'] = False


def reverse_bcd(bcd=''):
    if bcd:
        bcd_str = ''.join(re.findall(r'.{2}', bcd)[::-1])
        return bcd_str
    else:
        return ''

'''
用于把接收到的二进制数据包的粘包处理，以 b'\x16' 作为分隔符切分成以列表返回的多个单独的包
实际情景中存在包里面有\x16，所以用\x16\x68用为分隔符，切分后需要补回分隔符在原包中
(适用于tcp接收到的包)
'''
def split_package(msg_bin=b''):
    # 数据类型不对返回空
    if not isinstance(msg_bin, bytes):
        return []

    # 不存在粘包的情况（单个正常包）
    if is_checksum_pass(msg_bin):
        return [msg_bin]

    # 分隔符不存在返回原信息
    if b'\x16\x68' not in msg_bin:
        return [msg_bin]

    # 存在粘包的情况,大于等于2个粘包
    msg_bin_list = list(filter(lambda x: x not in b'', msg_bin.split(b'\x16\x68')))
    if len(msg_bin_list) < 2:  # 要确保能切分出两个包
        return []
    new_package_list = list(map(lambda x: b'\x68' + x + b'\x16', msg_bin_list))
    new_package_list[0] = new_package_list[0][1:]
    new_package_list[len(new_package_list) - 1] = new_package_list[len(new_package_list) - 1][0:-1]
    '''
    length = 0
    for new_package in new_package_list:
        length += len(new_package)
    if length % len(new_package_list) == 0:
        return new_package_list
    else:
        return []
    '''
    return new_package_list
