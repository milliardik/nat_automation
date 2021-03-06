"""
Скрипт выполняет следующую работу
    Загружает данные из источника по умолчанию локального файла (расположенного в месте размещения скрипта см. опцию --path-to)
    (Для github Обязательно заполнение опций командной строки --git-user и --git-token)
    Из полученных данных скрипт формирует конфигурацию списка достпуа, которую в последующем применят к устройству или
    группе устройств (см. аргумент groups командной строки) и обязательно размещенных в файле
    inventory_file.yaml (см. опцию --inventory-file)
    Пример использоватния (Windows)
    python .\nat_automation.py 172.30.22.7 --path-to https://api.github.com/repos/milliardik/nat_automation/contents/input_data
    --git-user milliardik --git-token [auth token https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token]
"""
import click
import yaml
import time
import base64
import socket
import logging
import requests

from typing import Tuple, List, Dict, Optional, Union
from ipaddress import IPv4Interface
from pathlib import Path

from scrapli import Scrapli
from scrapli.helper import textfsm_parse
from scrapli.exceptions import ScrapliAuthenticationFailed, ScrapliConnectionNotOpened

from dns.resolver import resolve, NXDOMAIN

from configurations import BASEDIR, INPUT_DATA_FILE, INVENTORY_FILE,  logger
# from configurations import GIT_ACCESS_TOKEN, GIT_ACCESS_USERNAME

SOCKET_TIMEOUT = 2
MIN_TTL = 604800
LAST_CREATED_INTERFACE = 0


def validate_ip(string: str) -> Optional[Union[bool, str]]:
    prefix = '32'
    if '/' in string:
        string, prefix = string.split('/')

    octets = string.split('.')

    if len(octets) == 4 and any(l.isdigit() and 0<int(l)<256 for l in octets) and 0<int(prefix)<33:
        return '{}/{}'.format('.'.join(octets), prefix)

    return False


def load_from_git(path_to, git_user, git_token):
    result = []
    # НЕОБХОДИМЫ ДОП ПРОВЕРКИ, НАЛИЧИЕ ПЕРЕМЕННЫХ GIT_ACCESS_USERNAME, GIT_ACCESS_TOKEN
    # ВОЗМОЖНО ЧТО ТО ЕЩЕ.
    # СЫРО
    file_response = requests.get(path_to, auth=(git_user, git_token))

    if file_response.ok:
        string = base64.b64decode(file_response.json()['content']).decode('utf-8')
        result = [line.strip() for line in string.split('\n')]
    else:
        if file_response.status_code == 401:
            log_level = logging.CRITICAL
            msg = f'ПРоверте данные авторизации на ресурсе {path_to}'
            logger.log(log_level, msg)

    return result


def load_data_from(path_to: str, git_user=None, git_token=None) -> List:
    log_level = logging.INFO
    msg = f'Данные пути {path_to} загружены успешно'

    if Path(path_to).exists():
        with open(path_to) as handler:
            result = [line.strip() for line in handler]
    else:
        result = load_from_git(path_to, git_user, git_token)

    if not result:
        log_level = logging.CRITICAL
        msg = f'Что то пошло не так, проверьте правильность набранного пути {path_to}'

    logger.log(log_level, msg)

    return result


def name_resolver(line: str) -> tuple:
    def dns_lookup(hostname: str) -> Tuple[int, list]:
        response = resolve(hostname)

        return response.rrset.ttl, [row.address for row in response]

    global MIN_TTL

    result = None, None

    if validate_ip(line):
        result = MIN_TTL, [IPv4Interface(line)]
    else:
        try:
            ttl, addresses = dns_lookup(line)
            addresses = [IPv4Interface(f'{ip}/32') for ip in addresses]
            result = ttl, addresses
        except NXDOMAIN:
            logger.log(logging.CRITICAL, f'Не распознаное имя {line}')

    return result


def prepare_data(path_to: str) -> Tuple[int, list]:
    global MIN_TTL

    min_ttl = MIN_TTL
    destination_hosts = list()

    for row in load_data_from(path_to):
            load_data = name_resolver(row)

            if load_data[1]: # Not Nonetype
                min_ttl = min_ttl if min_ttl < load_data[0] else load_data[0]
                destination_hosts.extend(load_data[1])
            else:
                logger.log(logging.CRITICAL, load_data)

    destination_hosts.sort()

    return min_ttl, destination_hosts


def get_devices(groups: list, path_to_file: Path) -> List[Dict]:
    def filter_by_ip(all_, ip):
        nonlocal result

        if ip in all_:
            result.append(dict(host=ip, **all_[ip]))
        else:
            logger.log(logging.CRITICAL, f'Устройство {ip} отсутствует в inventory_file')

    result = []

    with open(path_to_file) as f:
        data = yaml.load(f, Loader=yaml.FullLoader)

    all_ = data.get('all', [])

    if 'all' in groups:
        result.extend([dict(host=k, **all_[k]) for k in all_])
    else:
        for gname in groups:
            if validate_ip(gname):
                filter_by_ip(all_, gname)
            elif gname in data:
                ip_addresses = data.get(gname)
                for ip in ip_addresses:
                    filter_by_ip(all_, ip)
            else:
                print(f'{gname}: отсутствует в файле инвенторизации')
                print('Проверьте правильность веденных даных !')

    return result


def get_srs_or_dest(row: dict, dst=False) -> IPv4Interface:
    prefix = 'src_' if not dst else 'dst_'

    host = prefix + 'host'
    network = prefix + 'network'
    wildcard = prefix + 'wildcard'

    if not row[host]:
        result_str = f'{row.get(network)}/{row.get(wildcard)}'
    else:
        result_str = row.get(host) + '/32'

    return IPv4Interface(result_str)


def iface_to_str(ip_interface: IPv4Interface, with_='with_hostmask') -> str:
    ip, prefix = getattr(ip_interface, with_).split('/')

    if prefix == '0.0.0.0':
        result_str = f'host {ip}'
    else:
        result_str = f'{ip} {prefix}'

    return result_str


def create_acl_cfg(conn: Scrapli, acl_name: str, dst_ifaces: List[IPv4Interface], prev_dst_ifaces=[]) -> List:
    rows = [f'ip access-list ex {acl_name}']
    row_tpl = 'permit ip {source} {destination}'
    textfsm_tpl = BASEDIR.joinpath('cisco_ios_show_ip_access-lists.textfsm')

    cur_acl_cfg = conn.send_command(f'show ip access-list {acl_name}').result

    if not cur_acl_cfg:
        logger.log(logging.CRITICAL, f' Список доступа {acl_name} отсутствует')

    parsed_data = textfsm_parse(textfsm_tpl, cur_acl_cfg)[1:]
    srs_interfaces = set([get_srs_or_dest(row) for row in parsed_data])

    for cur_acl_row in parsed_data:
        src = get_srs_or_dest(cur_acl_row)
        dst = get_srs_or_dest(cur_acl_row, dst=True)

        if dst in dst_ifaces:
            dst_ifaces.remove(dst)
        else:
            if prev_dst_ifaces and dst not in prev_dst_ifaces:
                logger.log(logging.CRITICAL, f'Адрес {dst} добавлен вручную')
            rows.append('no ' + row_tpl.format(source=iface_to_str(src), destination=iface_to_str(dst)))

    for dst in dst_ifaces:
        for src in srs_interfaces:
            rows.append(row_tpl.format(source=iface_to_str(src), destination=iface_to_str(dst)))

    return rows


def check_port_alive(host: str, port=22) -> bool:
    global SOCKET_TIMEOUT

    result = False

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(SOCKET_TIMEOUT)

        code = s.connect_ex((host, port))

        if code == 0:
            s.close()
            result = True
    except Exception:
        pass

    return result


def create_loiface(csr, ip_interfaces, username, password):
    global LAST_CREATED_INTERFACE

    delete_cfg_tpl = 'no interface loopback{}'
    create_cfg_tpl = 'interface loopback{}\n ip address {}'

    tmp = list()
    for i, ip_interface in enumerate(ip_interfaces, 10):
        ip_address = ' '.join(ip_interface.with_netmask.split('/'))
        tmp.append(create_cfg_tpl.format(i, ip_address))

    delete_cfg = '\n!\n'.join([delete_cfg_tpl.format(_) for _ in range(10, LAST_CREATED_INTERFACE)])
    create_cfg = '\n!\n'.join(tmp)

    conn = connect_open(csr, username, password)
    if conn:
        if delete_cfg:
            logger.log(logging.INFO, f'Удалено {LAST_CREATED_INTERFACE} loopback интерфейсов ')
            conn.send_config(delete_cfg)

        logger.log(logging.INFO, f'Создано {len(tmp)} loopback интерфейсов ')
        conn.send_config(create_cfg)

    LAST_CREATED_INTERFACE = len(tmp)


def connect_open(
        host: str,
        username: str,
        password: str,
        platform='cisco_iosxe',
        transport='ssh',
        **kwargs) -> Optional[Union[Scrapli, bool]]:

    loglevel = logging.CRITICAL
    msg = f'Подключение к утройству {host} выполнено'

    result = False

    if not check_port_alive(host):
        msg = f'Устройство {host} не доступно'
    else:
        conn = Scrapli(
            host=host,
            auth_username=username,
            auth_password=password,
            transport='paramiko' if transport == 'ssh' else 'telnet',
            platform=platform,
            auth_strict_key=False,
            **kwargs
        )

        try:
            conn.open()
            result = conn
            loglevel = logging.INFO
        except ScrapliAuthenticationFailed:
            msg = 'Не верный логин или пароль.\n'
        except ScrapliConnectionNotOpened:
            msg = f'не удалось подключиться к устройству {host}\n'

    logger.log(loglevel, msg)
    return result


def connect_close(conn: Scrapli) -> None:
    # conn.send_command('copy running-config startup-config')
    conn.close()


@click.command()
@click.argument('groups', nargs=-1)
@click.option('-u', '--username', prompt='Username', required=True)
@click.password_option('-p', '--password', confirmation_prompt=False)
@click.option('--acl-name', type=str, default='130')
@click.option('--path-to', type=str, default=INPUT_DATA_FILE, show_default=True)
@click.option('--git-user', type=str)
@click.option('--git-token', type=str)
# @click.option('--name', type=click.Choice(['file', 'github']), default='file', show_default=True)
@click.option(
    '--inventory-file',
    type=click.Path(exists=True),
    default=str(INVENTORY_FILE), show_default=str(INVENTORY_FILE))
def cli(username, password, inventory_file, path_to, git_user, git_token, groups, acl_name):
    prev_dst_ifaces = list()
    devices = get_devices(groups, inventory_file)

    while devices:
        min_ttl, destination_hosts = prepare_data(path_to)

        if min_ttl == 0:
            time.sleep(2)
            continue

        start_time = time.time()

        # create_loiface('1.1.1.1', destination_hosts, username, password)

        for device in devices:
            host = device.get('host')
            platform = device.get('platform')

            conn = connect_open(host, username, password, platform=platform)

            if conn:
                acl_cfg = create_acl_cfg(conn, acl_name, destination_hosts.copy(), prev_dst_ifaces)
                prev_dst_ifaces = destination_hosts.copy()

                if len(acl_cfg) > 1:
                    conn.send_configs(acl_cfg)
                    logger.log(logging.INFO, 'Изменения применены успешно.')
                    connect_close(conn)
                else:
                    # Отсутствует спсиок доступа на устройстве
                    # Предусмотреть отправку ошибки на почту или сигнализировать др спопособом
                    pass
            else:
                # Нет подключения к устройству
                # Предусмотреть отправку ошибки на почту или сигнализировать др спопособом
                # чтоб можно было увидеть/обратить внимание на сообщение ошибки
                pass

        min_ttl -= int(time.time() - start_time - 1)

        if min_ttl > 0:
            logger.log(logging.INFO, f'Ожидание {min_ttl} сек ...')
            with click.progressbar(range(min_ttl)) as bar:
                for _ in bar:
                    time.sleep(1)

        # click.clear()


if __name__ == '__main__':
    cli()