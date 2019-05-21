#coding:utf-8
#!/usr/bin/env python3

__author__ = 'geyeg'

import socket
import select
import logging
import logging.handlers
from ws_protocol import *
from jgs import *
from decode import *
from assemble_packet import *

# ---------------------------------- 以下是接收处理 ----------------------------------------------------------------
def tcp_recv_handler(so_fd):
    global online_dev
    global post_q
    global fd_to_connector
    global fd_to_socket

    _concentrator = fd_to_connector.get(so_fd)
    so_conn = fd_to_socket[so_fd]
    try:
        data = so_conn.recv(8192)
    except socket.error as e:
        logging.error('timeout,connection closed:sock_fd={}&connector={}'.format(so_fd, _concentrator))
        server_receptionist.unregister(so_fd)
        fd_to_socket[so_fd].close()
        with lock:
            if fd_to_connector.get(so_fd) in online_dev:
                del(online_dev[fd_to_connector[so_fd]])
            if so_fd in fd_to_connector:
                del(fd_to_connector[so_fd])
            if so_fd in fd_to_socket:
                del(fd_to_socket[so_fd])
            if so_fd in fd_living_count:
                del(fd_living_count[so_fd])
        return ''

    if not data:
        logging.info('Connection closed by socket_fd={}&connector={}'.format(so_fd, _concentrator))
        server_receptionist.unregister(so_fd)
        fd_to_socket[so_fd].close()
        with lock:
            if fd_to_connector.get(so_fd) in online_dev:
                del(online_dev[fd_to_connector[so_fd]])
            if so_fd in fd_to_connector:
                del(fd_to_connector[so_fd])
            if so_fd in fd_to_socket:
                del(fd_to_socket[so_fd])
            if so_fd in fd_living_count:
                del(fd_living_count[so_fd])
        return ''

    logging.info('recv_hex_data:{}'.format((so_fd, bytes_to_show(data))))

    # 解决存在粘包的情况(仅适合一个包内有多个完整包)
    data_list = split_package(data)
    for single_data in data_list:
        recv_packet_bin_q.put((so_fd, single_data))


def recv_worker():
    while True:
        if recv_packet_bin_q.empty():
            time.sleep(1)
            continue

        so_fd, packet_bin = recv_packet_bin_q.get()
        if not packet_bin:
            logging.error('Get null value from receive queue.')
            continue
        try:
            semi_packet, body_hex = decode_head(packet_bin)
        except Exception as e:
            logging.error('decode head error:{}'.format(e))
            continue

        if not semi_packet:
            logging.error('decode binary protocol header error.')
            continue

        # 更新在线设备表
        _concentrator = semi_packet.get('concentrator_number')
        if not _concentrator:
            logging.error('Concentrator_number not found:{}'.format(semi_packet))
            continue
        with lock:
            if _concentrator in online_dev:
                online_dev[_concentrator]['living_count'] = 0  # 每次有连接，重置计数器
                online_dev[_concentrator]['fd'] = so_fd
            else:  # 设备不在列表时创建
                online_dev[_concentrator] = dict()
                online_dev[_concentrator]['fd'] = so_fd
                online_dev[_concentrator]['living_count'] = 0
                online_dev[_concentrator]['ser'] = 0
                online_dev[_concentrator]['is_sending'] = False
                online_dev[_concentrator]['is_catch_reply'] = False
                online_dev[_concentrator]['reply_cmd'] = ''
                online_dev[_concentrator]['reply_cmd_afn'] = ''
                online_dev[_concentrator]['id'] = ''
                fd_to_connector[so_fd] = _concentrator

        # 加入一些额外标记
        semi_packet['_c'] = 'apply_cmd'  # 上行

        if (semi_packet['FIR'] == 1 and semi_packet['FIN'] == 1) or NO_USE_FIR_FIN_FLAG:  # 独立完整包
            try:
                full_pack = decode_body(body_hex, semi_packet)
            except Exception as e:
                logging.error('decode body error:{}'.format(e))
                continue
            if semi_packet['CON'] == 1:  # 回复
                server_cmd_q.put(full_pack)
                logging.debug('add to reply queue:{}'.format(full_pack))
            if full_pack:
                logging.info('recv_hex_to_json:{}'.format(json.dumps(full_pack, indent=4)))
                # 放入上报队列
                if full_pack['_f'] in need_post_feature_list:  #在此列表之内的feature需要上报
                    post_q.put(full_pack)
                # 检测是否捕获回复指令
                if _concentrator in online_dev:
                    if online_dev[_concentrator]['is_catch_reply']:
                        if full_pack['_f'] == online_dev[_concentrator]['reply_cmd_afn']:
                            with lock:
                                online_dev[_concentrator]['reply_cmd'] = full_pack.copy()
            else:
                logging.error('packet body error:{}'.format(full_pack))
        else:  # 碎片包
            fragment_packet_q.put((semi_packet, body_hex))
            if semi_packet['CON'] == 1:  # 回复确认包
                server_cmd_q.put(semi_packet)
                logging.debug('add to reply queue:{}'.format(semi_packet))
            logging.debug('add fragment packet to queue')

    # 如果循环退出，报异常日志
    logging.critical('recv_worker is broken.')


'''
        # me_date = dict(
        #     concentrator_number='88888888',
        #     meter_number='11111111',
        #     value=27.12,
        #     upload_time='2018-06-03 23:30:07',
        #     collect_time='2018-06-03 23:30:10',
        #     body=dict(
        #         value=27.12,
        #         unit='m3'
        #     )
        # )
        # post_q.put(me_date)
'''
def http_post_worker():
    global post_q

    while True:
        if post_q.empty():
            time.sleep(0.5)
            continue

        post_command_data = []
        post_meter_data = []

        hy_cmd = post_q.get()
        # 转发到井岗山
        if hy_cmd.get('concentrator_number') in jgs_concentrators:
            jgs_q.put(hy_cmd)
        logging.debug('Get from post queue:{}'.format(json.dumps(hy_cmd)))
        cmd_list = convert_hy_to_server(hy_cmd)
        if not cmd_list:
            logging.error('convert hy pack to server pack (dict) failure.')
            continue

        if hy_cmd.get('feature') in ['upload_multiple_timing', 'upload_single_timing_lora',
                                     'upload_single_timing_lora_big', 'upload_single_timing_lora_big_15min',
                                     'upload_single', 'upload_single',
                                     'upload_sensor_pressure_multiple', 'upload_sensor_pressure_temperature',
                                     'upload_liquid_level', 'upload_valve_position']:
            post_meter_data = cmd_list
        elif hy_cmd.get('_f') == 'heartbeat':
            post_command_data = cmd_list
        else:
            logging.error('This message no need to post:{}'.format(hy_cmd))

        # post_meter_data = [me_date]
        if post_command_data:
            http_post(API_BASE_URL + '/command_data', post_command_data)
            # logging.info('post:{}'.format(post_command_data))
        if post_meter_data:
            http_post(API_BASE_URL + '/meter_data', post_meter_data)
            # 另外发一份到上海公司
            # if is_send_to_sh:
            #     sh_data = dict(list=post_meter_data)
            #     http_post(uri_meter_value_shanghai, sh_data, 1)

    logging.critical('http_post_worker is broken.')


# ---------------------------------- 以下是发送处理 ----------------------------------------------------------------
def send_worker():
    global server_cmd_q
    while True:
        if server_cmd_q.empty():
            time.sleep(0.5)
            continue

        # 从下发指令队列取出一条指令
        server_cmd_dict = server_cmd_q.get()
        _concentrator = server_cmd_dict['concentrator_number']
        # logging.debug('get_from_send_queue:{}'.format(server_cmd_dict))
        if _concentrator in online_dev:
            # if online_dev[_concentrator]['is_sending']:
            #     if server_cmd_dict['feature'] == 'heartbeat':
            #         pass
            #     else:
            #         server_cmd_q.put(server_cmd_dict)
            #         continue
            if server_cmd_dict['_c'] == 'assign_cmd':  # 下发指令
                if online_dev[_concentrator]['is_sending']:
                    # 如果有指令正在发送中，刚重新放入队列，等下次再发送
                    server_cmd_q.put(server_cmd_dict)
                    continue
                else:
                    # 无正在进行的下发指令就马上执行下发
                    with lock:
                        online_dev[_concentrator]['is_sending'] = True
                        online_dev[_concentrator]['id'] = server_cmd_dict['id']
                        threading.Thread(target=send_once_worker, args=(server_cmd_dict,)).start()
            else:  # 需回复的指令,无条件回复，无须理会是否有指令在下发
                threading.Thread(target=send_once_worker, args=(server_cmd_dict,)).start()
        else:
            logging.error('concentrator offline,can not send data [{}]'.format(server_cmd_dict))


def send_once_worker(server_cmd_dict):
    _concentrator = server_cmd_dict.get('concentrator_number')
    if not _concentrator:
        logging.error('connector number not found:{}'.format(server_cmd_dict))
        reset_send_status(_concentrator)
        return ''

    if server_cmd_dict['_c'] == 'assign_cmd':
        # 指令切分
        server_cmd_list = cmd_cutter(server_cmd_dict)

        # 开始逐一发送
        for server_cmd_dict in server_cmd_list:
            # 转为衡阳格式指令（字典）
            try:
                hy_cmd_dict = convert_server_to_hy(server_cmd_dict)
            except Exception as e:  # 转换指令格式失败，退出发送
                logging.error('Convert format error(server_socket to hy dict):{}'.format(server_cmd_dict))
                logging.error(e)
                reset_send_status(_concentrator)
                return ''

            if not hy_cmd_dict:
                logging.error('convert server command to HY command failure:empty.')
                reset_send_status(_concentrator)
                return ''

            # 转为二进制格式待发送
            try:
                byte_cmd = pack(hy_cmd_dict)
            except Exception as e:
                logging.error('hy_pack to hex_pack error:{}'.format(hy_cmd_dict))
                logging.error(e)
                reset_send_status(_concentrator)
                return ''
            if not byte_cmd:
                logging.error('pack command to bytes error:'.format(hy_cmd_dict))
                reset_send_status(_concentrator)
                return ''

            # 设置接收捕获特定指令
            with lock:
                if _concentrator in online_dev:
                    online_dev[_concentrator]['reply_cmd'] = ''
                    online_dev[_concentrator]['is_catch_reply'] = True
                    online_dev[_concentrator]['reply_cmd_afn'] = server_cmd_dict['feature']
                    online_dev[_concentrator]['ser'] = hy_cmd_dict['ser']
                else:
                    logging.error('concentrator offline,can not send data:{}'.format(hy_cmd_dict))
                    reset_send_status(_concentrator)
                    return ''

            logging.info('send command(dict):{}'.format(hy_cmd_dict))

            # 开始发送，失败重发
            for _i in range(5):
                is_reply_ok = False
                try:
                    if _concentrator in online_dev:
                        fd_to_socket[online_dev[_concentrator]['fd']].sendall(byte_cmd)
                except OSError as e:
                    logging.error('Send error,can not send the command:{}'.format(hy_cmd_dict))
                    logging.error(e)
                    with lock:
                        online_dev[_concentrator]['is_catch_reply'] = False
                        online_dev[_concentrator]['is_sending'] = False
                    return ''
                else:
                    logging.info('send_hex_data[{}]:{}'.format(_concentrator, bytes_to_show(byte_cmd)))
                time.sleep(2)  # 等待一会才去查找结果
                # 在online_dev中查找或等待回复
                for _j in range(15):
                    try:
                        reply_cmd = online_dev[_concentrator]['reply_cmd']
                    except Exception as e:
                        logging.error('reply command not found:'.format(hy_cmd_dict))
                        logging.error(e)
                    else:
                        if reply_cmd:
                            if reply_cmd['ser'] == hy_cmd_dict['ser'] and reply_cmd['_f'] == hy_cmd_dict['_f']:
                                is_reply_ok = True
                                break  # 有收到回复就不用重发了，退出循环
                    time.sleep(1)
                if is_reply_ok:
                    break  # 有收到回复继续退出本级循环

            # 清理状态
            with lock:
                if _concentrator in online_dev:
                    reset_send_status(_concentrator)
    else:  # 回复包发送
        try:
            hy_cmd_dict = convert_server_to_hy(server_cmd_dict)
        except Exception as e:
            logging.error('Convert format error(server to HY dict):{}'.format(server_cmd_dict))
            logging.error(e)
            # online_dev[server_cmd_dict['concentrator_number']]['is_sending'] = False
            return ''
        if not hy_cmd_dict:
            logging.error('convert server command to HY command failure:empty.')
            # online_dev[server_cmd_dict['concentrator_number']]['is_sending'] = False
            return ''
        logging.info('send dict:{}'.format(hy_cmd_dict))

        # 转为二进制格式指令
        try:
            byte_cmd = pack(hy_cmd_dict)
        except Exception as e:
            logging.error('Pack error:{}'.format(hy_cmd_dict))
            logging.error(e)
            # online_dev[server_cmd_dict['concentrator_number']]['is_sending'] = False
            return ''

        if not byte_cmd:
            logging.error('pack command to bytes failure.')
            # online_dev[server_cmd_dict['concentrator_number']]['is_sending'] = False
            return ''

        if _concentrator in online_dev:
            if 'fd' in online_dev[_concentrator]:
                try:
                    fd_to_socket[online_dev[_concentrator]['fd']].sendall(byte_cmd)
                except OSError as e:
                    logging.error('concentrator offline,can not send data:{}'.format(hy_cmd_dict))
                    logging.error(e)
                else:
                    logging.info('send_hex_data[{}]:{}'.format(_concentrator, bytes_to_show(byte_cmd)))
            else:
                logging.error('concentrator offline,can not send data [{}]'.format(hy_cmd_dict))
                with lock:
                    del(online_dev[_concentrator])
        else:
            logging.error('concentrator offline,can not send data [{}]'.format(hy_cmd_dict))


def http_get_worker():
    global server_cmd_q

    while True:
        time.sleep(1.5)

        # 从服务器中读取下发指令
        try:
            response = requests.get(API_BASE_URL + '/command_data', headers=headers, params={'ip': ip, 'port': port})
            if response.status_code != 200:
                logging.error('http_code:{}'.format(response.status_code))
        except Exception as e:
            logging.error('http get error:{}'.format(e))
            continue
        if not response.text:
            time.sleep(1)
            continue
        logging.debug('http_get[text]:{}'.format(response.text))
        # 转为字典格式
        try:
            server_cmd_list = json.loads(response.text)
        except Exception as e:
            logging.error('Unknow json format:{}'.format(response.text))
            logging.error(e)
            continue
        # 校验收到的数据包是否列表形式
        if not isinstance(server_cmd_list, list):
            logging.error('List must in json level 1:{}'.format(server_cmd_list))
            continue

        # 过滤已知的暂未能处理的指令 ***
        # _f = server_socket_cmd_list.get('feature')

        logging.debug('http_get_command_from_server:{}'.format(server_cmd_list))

        # 服务器下取出的指令是一个列表，列表内每个字典属于一个集中器的一条完整指令，拆分开按顺序放入 server_cmd_q 队列
        for cmd in server_cmd_list:
            # 如果不是dict格式则丢弃
            if not isinstance(cmd, dict):
                logging.error('The json level 2 must be dict:{}'.format(cmd))
                continue
            # 检查是否存在消息id
            if 'id' not in cmd:
                logging.error('Message id not found:{}'.format(cmd))
                continue

            _concentrator_number = cmd.get('concentrator_number')
            if not _concentrator_number:
                logging.error('Connector number not found in the json:{}'.format(cmd))
                continue
            if _concentrator_number in online_dev:  # 检果在线设备列表是否存在当前集中器号
                '''
                if online_dev[_concentrator_number]['is_sending']:
                    server_reply_dict = dict(
                        id=cmd['id'],
                        result='busy'
                    )
                    post_q.put(server_reply_dict)
                    # logging.info('Busy:{}'.format(server_socket_reply_dict))
                else:
                    cmd['_c'] = 'assign_cmd'
                    # print('debug:{}'.format(cmd))
                    # 关键字转换 90EF的集抄城要转换
                    # if cmd['feature'] == 'runonce_upload_multiple_timing' and cmd['body']['protocol'] == '90ef':
                    #     cmd['feature'] = 'runonce_upload_multiple_timing_lora'
                    logging.debug('http_get_command_from_server:{}'.format(cmd))
                    server_cmd_q.put(cmd)
                '''
                cmd['_c'] = 'assign_cmd'
                # 指令名称feature转换，只转换下发，接收还是原来指令名称
                if instruction_translation_dict:
                    new_feature = instruction_translation_dict.get(cmd.get('feature'))
                    if new_feature:
                        cmd['feature'] = new_feature
                server_cmd_q.put(cmd)
                logging.debug('http_get_command_from_server:{}'.format(cmd))
            else:
                server_reply_dict = dict(
                    id=cmd['id'],
                    result='offline'
                )
                post_q.put(server_reply_dict)
                logging.error('Send error, concentrator offline.')
    logging.critical('http_get_worker is broken.')


def online_dev_man():
    global fd_living_count
    global online_dev
    global thread_http_get_worker
    global thread_http_post_worker
    global thread_send_worker
    global thread_http_post_worker_jgs
    global thread_recv_worker
    global thread_assemble_worker

    loop_time_count = 0
    while True:
        loop_time_count += 1
        if loop_time_count > 1000:
            loop_time_count = 0
        time.sleep(1)

        if loop_time_count % 20 == 0:
            concentrator_list = list(online_dev.keys()).copy()
            logging.info('online concentrator:{}'.format(concentrator_list))  # 输出在线集中器列表
            logging.info('q_post:{} | q_send:{}'.format(post_q.qsize(), server_cmd_q.qsize()))  # 输出队列状态
            current_thread_name = [_t.getName() for _t in threading.enumerate()]
            logging.info('current thread:{}'.format(current_thread_name))  # 输出当前线程名称
            logging.info('fd_living_list:{}'.format(fd_living_count))
            logging.info('fd_to_connector:{}'.format(fd_to_connector))
            if 'send_worker' not in current_thread_name:
                logging.critical('send_worker is broken, try to restart it.')
                thread_send_worker = threading.Thread(target=send_worker, args=())
                thread_send_worker.setName('send_worker')
                thread_send_worker.setDaemon(True)
                thread_send_worker.start()
            if 'http_post_worker' not in current_thread_name:
                logging.critical('http_post_worker is broken, try to restart it.')
                thread_http_post_worker = threading.Thread(target=http_post_worker, args=())
                thread_http_post_worker.setName('http_post_worker')
                thread_http_post_worker.setDaemon(True)
                thread_http_post_worker.start()
            if 'http_get_worker' not in current_thread_name:
                logging.critical('http_get_worker is broken, try to restart it.')
                thread_http_get_worker = threading.Thread(target=http_get_worker, args=())
                thread_http_get_worker.setName('http_get_worker')
                thread_http_get_worker.setDaemon(True)
                thread_http_get_worker.start()

            if 'http_post_worker_jgs' not in current_thread_name:
                logging.critical('http_post_worker_jgs is broken, try to restart it.')
                thread_http_post_worker_jgs = threading.Thread(target=http_post_worker_jgs, args=())
                thread_http_post_worker_jgs.setName('http_post_worker_jgs')
                thread_http_post_worker_jgs.setDaemon(True)
                thread_http_post_worker_jgs.start()

            if 'recv_worker' not in current_thread_name:
                logging.critical('recv_worker is broken, try to restart it.')
                thread_recv_worker = threading.Thread(target=recv_worker, args=())
                thread_recv_worker.setName('recv_worker')
                thread_recv_worker.setDaemon(True)
                thread_recv_worker.start()

            if 'assemble_worker' not in current_thread_name:
                logging.critical('assemble_worker is broken, try to restart it.')
                thread_assemble_worker = threading.Thread(target=assemble_worker, args=())
                thread_assemble_worker.setName('assemble_worker')
                thread_assemble_worker.setDaemon(True)
                thread_assemble_worker.start()

        concentrator_list = list(online_dev.keys()).copy()
        with lock:
            for _concentrator in concentrator_list:
                if 'living_count' in online_dev[_concentrator]:
                    if online_dev[_concentrator]['living_count'] > TIME_OUT:
                        _fd = online_dev[_concentrator]['fd']
                        if _fd in fd_to_socket:
                            fd_to_socket[_fd].close()
                            server_receptionist.unregister(_fd)
                        if _fd in fd_living_count:
                            del(fd_living_count[_fd])
                        if _fd in fd_to_connector:
                            del(fd_to_connector[_fd])
                        if _fd in fd_to_socket:
                            del(fd_to_socket[_fd])
                        if _concentrator in online_dev:
                            del(online_dev[_concentrator])
                        logging.info('no heartbeat timeout:[concentrator={}]'.format(_concentrator))
                    else:
                        online_dev[_concentrator]['living_count'] += 1

        fd_living_count_list = list(fd_living_count.keys()).copy()
        with lock:
            for _fd in fd_living_count_list:
                if fd_living_count[_fd] > 300:
                    _ip = ''
                    _port = ''
                    if _fd in fd_to_socket:
                        _ip, _port = fd_to_socket[_fd].getpeername()
                    logging.error('socket timeout:[fd={},ip={},port={},concentrator={}]'
                                  .format(_fd, _ip, _port, fd_to_connector.get(_fd)))
                    if fd_to_connector.get(_fd) in online_dev:
                        del(online_dev[fd_to_connector.get(_fd)])
                    if _fd in fd_to_socket:
                        fd_to_socket[_fd].close()
                        server_receptionist.unregister(_fd)
                    if _fd in fd_to_socket:
                        del(fd_to_socket[_fd])
                    if _fd in fd_to_connector:
                        del(fd_to_connector[_fd])
                    del(fd_living_count[_fd])
                else:
                    fd_living_count[_fd] += 1


if __name__ == '__main__':
    # 定义日志输出格式
    logger = logging.getLogger('')
    # logger.setLevel(logging.INFO)
    fmt_str = '%(asctime)s - %(levelname)s - %(threadName)s - %(message)s'
    # 初始化
    logging.basicConfig(level=logging.INFO, filename=log_file, filemode='a+')
    # logging.basicConfig(level=logging.INFO)
    # 创建TimedRotatingFileHandler处理对象
    # 间隔3600(S)创建新的名称为myLog%Y%m%d_%H%M%S.log的文件，并一直占用myLog文件。
    files_handle = logging.handlers.TimedRotatingFileHandler(log_file, when='H', interval=8, backupCount=30)
    # 设置日志文件后缀，以当前时间作为日志文件后缀名。
    files_handle.suffix = '%Y%m%d_%H%M%S.log'
    files_handle.extMatch = re.compile(r'^\d{4}\d{2}\d{2}_\d{2}\d{2}\d{2}')
    # 设置日志输出级别和格式
    files_handle.setLevel(logging.INFO)
    files_handle.setFormatter(logging.Formatter(fmt_str))
    # 添加到日志处理对象集合
    logger.handlers.pop()
    logger.addHandler(files_handle)

    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # 设置IP地址复用，让端口释放后立即就可以被再次使用
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # 设置协议整体的超时
    '''
    TCP_KEEPCNT 覆盖  tcp_keepalive_probes，默认9（次）
    TCP_KEEPIDLE 覆盖 tcp_keepalive_time，默认7200（秒）
    TCP_KEEPINTVL 覆盖 tcp_keepalive_intvl，默认75（秒）

    TCP_KEEPDILE 设置连接上如果没有数据发送的话，多久后发送keepalive探测分组，单位是秒
    TCP_KEEPINTVL 前后两次探测之间的时间间隔，单位是秒 两个探测的时间间隔，默认值为 150 即 75 秒
    TCP_KEEPCNT 关闭一个非活跃连接之前的最大重试次数 (判定断开前的KeepAlive探测次数)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    s.setsockopt(socket.SOL_TCP, socket.SO_KEEPIDEL, 10)
    s.setsockopt(socket.SOL_TCP, socket.SO_KEEPINTVL, 3)
    s.setsockopt(socket.SOL_TCP, socket.SO_KEEPCNT, 2)
    '''
    # server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 600)
    server_socket.setsockopt(socket.SOL_TCP, socket.TCP_KEEPIDLE, 300)
    server_socket.setsockopt(socket.SOL_TCP, socket.TCP_KEEPINTVL, 75)
    server_socket.setsockopt(socket.SOL_TCP, socket.TCP_KEEPCNT, 3)

    logging.info('socket created.')
    server_socket.bind((HOST, PORT))
    server_socket.listen(1024)
    logging.info('listen started.')
    server_socket.setblocking(False)
    # 创建epoll事件对象，后续要监控的事件添加到其中
    server_receptionist = select.epoll()
    # 注册服务器监听fd到等待读事件集合
    server_receptionist.register(server_socket.fileno(), select.EPOLLIN)
    logging.info('register to epoll:fileno-{}'.format(server_socket.fileno()))
    fd_to_socket[server_socket.fileno()] = server_socket

    thread_recv_worker = threading.Thread(target=recv_worker, args=())
    thread_recv_worker.setName('recv_worker')
    thread_recv_worker.setDaemon(True)
    thread_recv_worker.start()

    thread_http_get_worker = threading.Thread(target=http_get_worker, args=())
    thread_http_get_worker.setName('http_get_worker')
    thread_http_get_worker.setDaemon(True)
    thread_http_get_worker.start()

    thread_http_post_worker = threading.Thread(target=http_post_worker, args=())
    thread_http_post_worker.setName('http_post_worker')
    thread_http_post_worker.setDaemon(True)
    thread_http_post_worker.start()

    thread_send_worker = threading.Thread(target=send_worker, args=())
    thread_send_worker.setName('send_worker')
    thread_send_worker.setDaemon(True)
    thread_send_worker.start()

    thread_online_dev_man = threading.Thread(target=online_dev_man, args=())
    thread_online_dev_man.setName('online_dev_man')
    thread_online_dev_man.setDaemon(True)
    thread_online_dev_man.start()

    # post到井岗山专用线程
    thread_http_post_worker_jgs = threading.Thread(target=http_post_worker_jgs, args=())
    thread_http_post_worker_jgs.setName('http_post_worker_jgs')
    thread_http_post_worker_jgs.setDaemon(True)
    thread_http_post_worker_jgs.start()

    # 启动碎片包组装线程
    thread_assemble_worker = threading.Thread(target=assemble_worker, args=())
    thread_assemble_worker.setName('assemble_worker')
    thread_assemble_worker.setDaemon(True)
    thread_assemble_worker.start()

    while True:
        events = server_receptionist.poll()
        if not events:
            continue
        for fd, event in events:
            if fd == server_socket.fileno():  # 可以超进值，如果留空，一直阻塞到有数据才返回结果
                # 如果活动socket为当前服务器socket，表示有新连接
                connection, address = server_socket.accept()
                # connection.settimeout(600)
                # connection.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 600)
                # connection.setsockopt(socket.SOL_TCP, socket.TCP_KEEPIDLE, 600)
                # connection.setsockopt(socket.SOL_TCP, socket.TCP_KEEPINTVL, 150)
                # connection.setsockopt(socket.SOL_TCP, socket.TCP_KEEPCNT, 3)
                new_fd = connection.fileno()
                connection.setblocking(False)
                server_receptionist.register(connection.fileno(),
                                             select.EPOLLIN | select.EPOLLERR | select.EPOLLHUP)
                fd_to_socket[connection.fileno()] = connection  # 加入新socket
                fd_living_count[new_fd] = 0  # 初始化fd的计数器
                logging.info('New connection comes from {}:{}'.format(address[0], address[1]))
            elif event & select.EPOLLIN:
                # 可读事件,接收数据
                fd_living_count[fd] = 0  # 重置计数器
                tcp_recv_handler(fd)
            elif event & select.EPOLLHUP:
                # 关闭端口事件
                server_receptionist.unregister(fd)
                fd_to_socket[fd].close()
                del(fd_to_socket[fd])
                print('hup')
            elif event & select.EPOLLERR:
                # 异常事件
                server_receptionist.unregister(fd)
                fd_to_socket[fd].close()
                del(fd_to_socket[fd])
                print('hup')

    # 在epoll中注销服务端文件句柄
    server_receptionist.unregister(server_socket.fileno())
    server_receptionist.close()
    server_socket.close()