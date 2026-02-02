#!/usr/bin/env python3
"""
Nmap Scan Analyzer
Автоматизирует сканирование Nmap с анализом результатов и генерацией отчетов
"""

import argparse
import sys
import os
import re
import subprocess
import logging
from datetime import datetime
from pathlib import Path
import xml.etree.ElementTree as ET
from collections import defaultdict
import shutil
import time
import threading
import queue

class ProgressTracker:
    """Класс для отслеживания прогресса сканирования"""
    def __init__(self, target, logger):
        self.target = target
        self.logger = logger
        self.start_time = None
        self.last_update = None
        self.current_host = None
        self.current_port = None
        self.total_hosts = None
        self.scanned_hosts = 0
        self.is_network_scan = False
        self.lock = threading.Lock()
        
    def start(self):
        """Начать отслеживание прогресса"""
        self.start_time = datetime.now()
        self.last_update = self.start_time
        
        # Определяем тип сканирования
        if '/' in self.target or '-' in self.target:
            self.is_network_scan = True
            parts = self.target.split('/')
            if len(parts) > 1:
                # Пытаемся определить количество хостов в сети
                try:
                    cidr = int(parts[1])
                    if cidr <= 32:
                        self.total_hosts = 2 ** (32 - cidr)
                        if cidr <= 30:  # Исключаем сетевой и широковещательный адреса
                            self.total_hosts -= 2
                except:
                    pass
        
        self.logger.info(f"Начинаем отслеживание прогресса для цели: {self.target}")
        
    def update(self, line):
        """Обновить прогресс на основе строки вывода Nmap"""
        if not line:
            return
            
        line_lower = line.lower()
        
        with self.lock:
            # Определяем текущий хост
            host_match = re.search(r'scanning\s+(\d+\.\d+\.\d+\.\d+)', line_lower)
            if host_match:
                self.current_host = host_match.group(1)
                self.scanned_hosts += 1
                
            # Определяем текущий порт
            port_match = re.search(r'(\d+)/\w+\s+port', line_lower)
            if port_match:
                self.current_port = port_match.group(1)
                
            # Обнаружение завершения сканирования хоста
            if 'nmap scan report' in line_lower:
                self.scanned_hosts += 1
                
    def get_progress(self):
        """Получить текущий прогресс в процентах"""
        if not self.total_hosts or self.total_hosts <= 0:
            return None
            
        if self.scanned_hosts > self.total_hosts:
            return 100
            
        progress = (self.scanned_hosts / self.total_hosts) * 100
        return min(100, progress)
        
    def get_elapsed_time(self):
        """Получить прошедшее время"""
        if not self.start_time:
            return "00:00:00"
            
        elapsed = datetime.now() - self.start_time
        hours, remainder = divmod(int(elapsed.total_seconds()), 3600)
        minutes, seconds = divmod(remainder, 60)
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"
        
    def get_status_string(self):
        """Получить строку статуса"""
        status = []
        
        if self.current_host:
            status.append(f"Хост: {self.current_host}")
            
        if self.current_port:
            status.append(f"Порт: {self.current_port}")
            
        if self.scanned_hosts > 0 and self.total_hosts:
            progress = self.get_progress()
            if progress is not None:
                status.append(f"Прогресс: {progress:.1f}% ({self.scanned_hosts}/{self.total_hosts} хостов)")
                
        elapsed = self.get_elapsed_time()
        status.append(f"Время: {elapsed}")
        
        return " | ".join(status)

class NmapScanner:
    def __init__(self, output_dir, nmap_args=None):
        self.output_dir = Path(output_dir)
        self.logs_dir = self.output_dir / "logs"
        self.reports_dir = self.output_dir / "reports"
        self.nmap_args = nmap_args if nmap_args else "-sV --top-ports 100"

        # Создание директорий
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.logs_dir.mkdir(exist_ok=True)
        self.reports_dir.mkdir(exist_ok=True)

        # Настройка логирования
        self.setup_logging()

        # Словарь для сопоставления сервисов и портов
        self.service_ports = {
            'web': [80, 443, 8080, 8443, 8000, 3000, 9000],
            'ftp': [20, 21],
            'ssh': [22],
            'telnet': [23],
            'smtp': [25, 465, 587],
            'dns': [53],
            'dhcp': [67, 68],
            'tftp': [69],
            'http-proxy': [3128, 8080, 8888],
            'snmp': [161],
            'ldap': [389, 636],
            'smb': [137, 138, 139, 445],
            'mysql': [3306],
            'postgresql': [5432],
            'mongodb': [27017],
            'rdp': [3389],
            'vnc': [5900, 5901],
            'redis': [6379],
            'elasticsearch': [9200, 9300],
            'docker': [2375, 2376],
            'kubernetes': [6443, 10250],
            'jenkins': [8080],
        }

        self.known_services = {
            80: 'HTTP',
            443: 'HTTPS',
            22: 'SSH',
            21: 'FTP',
            25: 'SMTP',
            53: 'DNS',
            3389: 'RDP',
            3306: 'MySQL',
            5432: 'PostgreSQL',
            6379: 'Redis',
            27017: 'MongoDB',
            9200: 'Elasticsearch',
        }

    def setup_logging(self):
        """Настройка системы логирования"""
        timestamp = datetime.now().strftime("%H_%M_%S_%d_%m")
        log_file = self.logs_dir / f"{timestamp}.txt"

        # Логгер для вывода в консоль и файл
        self.logger = logging.getLogger('NmapScanner')
        self.logger.setLevel(logging.INFO)

        # Форматтер
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

        # Обработчик для файла
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setFormatter(formatter)

        # Обработчик для консоли (без форматирования для прогресс-бара)
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)

        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)

        self.logger.info(f"Инициализирован сканер. Директория: {self.output_dir}")
        self.logger.info(f"Аргументы Nmap: {self.nmap_args}")

    def print_progress_bar(self, iteration, total, prefix='', suffix='', length=50, fill='█'):
        """
        Выводит прогресс-бар в консоль
        
        Parameters:
        iteration - текущая итерация (int)
        total - общее количество итераций (int)
        prefix - префикс строки (str)
        suffix - суффикс строки (str)
        length - длина прогресс-бара в символах (int)
        fill - символ заполнения (str)
        """
        percent = ("{0:.1f}").format(100 * (iteration / float(total)))
        filled_length = int(length * iteration // total)
        bar = fill * filled_length + '-' * (length - filled_length)
        
        # Сохраняем позицию курсора для анимации
        sys.stdout.write('\r')
        sys.stdout.write(f'{prefix} |{bar}| {percent}% {suffix}')
        sys.stdout.flush()
        
        # Если завершено, переходим на новую строку
        if iteration == total:
            print()

    def estimate_scan_time(self, target, nmap_args):
        """Оценить время сканирования"""
        self.logger.info("Оценка времени сканирования...")
        
        estimated_time = "неизвестно"
        
        # Определяем количество портов
        if "-p-" in nmap_args or "--all-ports" in nmap_args:
            ports = 65535
            port_info = "все порты (65535)"
        elif "--top-ports" in nmap_args:
            match = re.search(r'--top-ports\s+(\d+)', nmap_args)
            if match:
                ports = int(match.group(1))
                port_info = f"топ {ports} портов"
            else:
                ports = 100
                port_info = "топ 100 портов"
        elif "-p" in nmap_args:
            # Пытаемся разобрать диапазон портов
            match = re.search(r'-p\s+([\d,\-\s]+)', nmap_args)
            if match:
                port_range = match.group(1)
                # Простая оценка - считаем максимальный порт
                ports = 1000  # Консервативная оценка
                port_info = f"указанные порты ({port_range})"
            else:
                ports = 1000
                port_info = "указанные порты"
        else:
            ports = 1000
            port_info = "стандартные порты"
        
        # Определяем количество хостов
        if '/' in target:
            parts = target.split('/')
            try:
                cidr = int(parts[1])
                hosts = 2 ** (32 - cidr)
                if cidr <= 30:
                    hosts -= 2
                host_info = f"{hosts} хостов в сети {target}"
            except:
                hosts = 100
                host_info = f"сеть {target}"
        elif '-' in target:
            # Диапазон IP
            hosts = 254  # Консервативная оценка
            host_info = f"диапазон {target}"
        else:
            hosts = 1
            host_info = f"один хост {target}"
        
        # Оценка времени (очень приблизительная)
        # Базовое время на порт: 0.1-1 секунда в зависимости от типа сканирования
        base_time_per_port = 0.5
        
        if "-sS" in nmap_args:
            base_time_per_port = 0.1  # SYN scan быстрее
        elif "-sT" in nmap_args:
            base_time_per_port = 0.3  # TCP connect медленнее
        elif "-sU" in nmap_args:
            base_time_per_port = 2.0  # UDP scan намного медленнее
        
        if "-T0" in nmap_args or "-T1" in nmap_args:
            base_time_per_port *= 5
        elif "-T2" in nmap_args:
            base_time_per_port *= 2
        elif "-T3" in nmap_args:
            base_time_per_port *= 1
        elif "-T4" in nmap_args or "-T5" in nmap_args:
            base_time_per_port *= 0.5
        
        total_seconds = hosts * ports * base_time_per_port
        
        if total_seconds < 60:
            estimated_time = f"~{int(total_seconds)} секунд"
        elif total_seconds < 3600:
            minutes = total_seconds / 60
            estimated_time = f"~{minutes:.1f} минут"
        elif total_seconds < 86400:
            hours = total_seconds / 3600
            estimated_time = f"~{hours:.1f} часов"
        else:
            days = total_seconds / 86400
            estimated_time = f"~{days:.1f} дней"
        
        self.logger.info(f"Оценка: {host_info}, {port_info}")
        self.logger.info(f"Примерное время сканирования: {estimated_time}")
        
        print(f"\n📊 ОЦЕНКА СКАНИРОВАНИЯ:")
        print(f"   Цель: {host_info}")
        print(f"   Порты: {port_info}")
        print(f"   ⏱️  Примерное время: {estimated_time}")
        
        if total_seconds > 300:  # Больше 5 минут
            print(f"   ⚠️  Это может занять некоторое время...")
            print(f"   💡 Совет: Для прерывания нажмите Ctrl+C")
        
        print()

    def run_nmap_scan(self, target):
        """Выполнение сканирования Nmap с отображением прогресса"""
        self.logger.info(f"Начинаю сканирование цели: {target}")
        
        # Оценка времени сканирования
        self.estimate_scan_time(target, self.nmap_args)
        
        # Имена файлов для результатов
        xml_output = self.reports_dir / "scan_results.xml"
        normal_output = self.reports_dir / "scan_results.txt"
        
        # Команда для выполнения сканирования
        cmd = f"nmap {self.nmap_args} -oX {xml_output} -oN {normal_output} {target}"
        
        self.logger.info(f"Выполняю команду: {cmd}")
        print(f"\n🚀 Запуск сканирования...")
        print(f"📝 Команда: {cmd}")
        
        # Инициализация трекера прогресса
        progress_tracker = ProgressTracker(target, self.logger)
        progress_tracker.start()
        
        # Очередь для вывода
        output_queue = queue.Queue()
        
        def read_output(pipe, queue):
            """Чтение вывода из pipe в отдельном потоке"""
            try:
                for line in iter(pipe.readline, ''):
                    if line:
                        queue.put(line)
                pipe.close()
            except:
                pass
        
        try:
            # Запускаем процесс
            process = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            # Запускаем потоки для чтения вывода
            stdout_thread = threading.Thread(
                target=read_output,
                args=(process.stdout, output_queue)
            )
            stderr_thread = threading.Thread(
                target=read_output,
                args=(process.stderr, output_queue)
            )
            
            stdout_thread.daemon = True
            stderr_thread.daemon = True
            stdout_thread.start()
            stderr_thread.start()
            
            # Сбор вывода и отображение прогресса
            last_progress_update = time.time()
            lines_buffer = []
            
            while True:
                # Проверяем завершение процесса
                if process.poll() is not None:
                    # Читаем оставшийся вывод
                    while not output_queue.empty():
                        line = output_queue.get_nowait()
                        if line:
                            lines_buffer.append(line)
                            progress_tracker.update(line)
                    break
                
                # Читаем вывод
                try:
                    line = output_queue.get(timeout=0.1)
                    if line:
                        lines_buffer.append(line)
                        progress_tracker.update(line)
                        
                        # Показываем информативные строки
                        if any(keyword in line.lower() for keyword in 
                               ['discovered', 'scanning', 'nmap scan report', 'port', 'service']):
                            print(f"   ℹ️  {line.strip()}")
                            
                except queue.Empty:
                    pass
                
                # Обновляем прогресс-бар каждые 0.5 секунд
                current_time = time.time()
                if current_time - last_progress_update > 0.5:
                    status = progress_tracker.get_status_string()
                    if status:
                        print(f"\r📊 {status}", end='', flush=True)
                    last_progress_update = current_time
            
            # Ждем завершения потоков
            stdout_thread.join(timeout=1)
            stderr_thread.join(timeout=1)
            
            # Получаем код возврата
            return_code = process.wait()
            
            if return_code == 0:
                print(f"\n✅ Сканирование успешно завершено!")
                self.logger.info("Сканирование успешно завершено")
                
                # Сохраняем вывод в лог
                full_output = ''.join(lines_buffer)
                if len(full_output) > 1000:
                    self.logger.info(f"Вывод Nmap (первые 1000 символов): {full_output[:1000]}...")
                else:
                    self.logger.info(f"Вывод Nmap: {full_output}")
                
                return xml_output
            else:
                print(f"\n❌ Nmap завершился с ошибкой (код: {return_code})")
                self.logger.error(f"Nmap завершился с кодом ошибки: {return_code}")
                
                # Выводим ошибки
                error_lines = [line for line in lines_buffer if 'error' in line.lower()]
                for error_line in error_lines[:5]:  # Первые 5 ошибок
                    print(f"   🔴 {error_line.strip()}")
                
                return None
                
        except KeyboardInterrupt:
            print(f"\n\n🛑 Получен сигнал прерывания (Ctrl+C)")
            self.logger.warning("Сканирование прервано пользователем")
            
            if 'process' in locals():
                print("   ⏳ Останавливаю сканирование...")
                process.terminate()
                
                try:
                    process.wait(timeout=5)
                    print("   ✅ Сканирование остановлено")
                except subprocess.TimeoutExpired:
                    process.kill()
                    print("   ⚠️  Процесс принудительно завершен")
            
            # Проверяем, создались ли файлы
            if xml_output.exists():
                file_size = xml_output.stat().st_size
                if file_size > 100:
                    print(f"   📁 Частичные результаты сохранены ({file_size} байт)")
                    self.logger.info(f"Частичные результаты сохранены ({file_size} байт)")
                    return xml_output
            
            print("   ❌ Результаты не найдены или файлы пустые")
            return None
            
        except Exception as e:
            print(f"\n❌ Непредвиденная ошибка: {e}")
            self.logger.error(f"Непредвиденная ошибка при сканировании: {e}")
            import traceback
            self.logger.error(f"Трассировка: {traceback.format_exc()}")
            return None

    def parse_nmap_xml(self, xml_file):
        """Парсинг XML вывода Nmap"""
        self.logger.info(f"Парсинг XML файла: {xml_file}")
        print(f"\n📊 Анализ результатов...")

        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()

            hosts_data = []
            total_hosts = len(root.findall('host'))
            processed = 0

            for host in root.findall('host'):
                host_info = self.parse_host(host)
                if host_info:
                    hosts_data.append(host_info)
                
                processed += 1
                progress = (processed / total_hosts) * 100 if total_hosts > 0 else 0
                print(f"\r   📋 Обработано хостов: {processed}/{total_hosts} ({progress:.1f}%)", end='', flush=True)

            print(f"\n✅ Найдено хостов: {len(hosts_data)}")
            self.logger.info(f"Найдено хостов: {len(hosts_data)}")
            return hosts_data

        except ET.ParseError as e:
            self.logger.error(f"Ошибка парсинга XML: {e}")
            print(f"❌ Ошибка при разборе XML файла")
            return []
        except Exception as e:
            self.logger.error(f"Ошибка при обработке XML: {e}")
            print(f"❌ Ошибка при обработке результатов")
            return []

    def parse_host(self, host_element):
        """Парсинг информации об одном хосте"""
        try:
            # Получение адреса
            address_elem = host_element.find(".//address[@addrtype='ipv4']")
            if address_elem is None:
                return None

            ip_address = address_elem.get('addr')

            # Получение имени хоста
            hostname_elem = host_element.find(".//hostname")
            hostname = hostname_elem.get('name') if hostname_elem is not None else "Unknown"

            # Получение портов
            ports_data = []
            ports_element = host_element.find('ports')

            if ports_element is not None:
                total_ports = len(ports_element.findall('port'))
                processed_ports = 0
                
                for port_element in ports_element.findall('port'):
                    port_info = self.parse_port(port_element)
                    if port_info:
                        ports_data.append(port_info)
                    
                    processed_ports += 1
                    # Тихий прогресс для каждого хоста

            return {
                'ip': ip_address,
                'hostname': hostname,
                'ports': ports_data
            }

        except Exception as e:
            self.logger.error(f"Ошибка парсинга хоста: {e}")
            return None

    def parse_port(self, port_element):
        """Парсинг информации о порте"""
        try:
            port_id = port_element.get('portid')
            protocol = port_element.get('protocol')

            state_elem = port_element.find('state')
            state = state_elem.get('state') if state_elem is not None else "unknown"

            if state != 'open':
                return None

            service_elem = port_element.find('service')
            service_name = service_elem.get('name') if service_elem is not None else "unknown"
            service_product = service_elem.get('product', '')
            service_version = service_elem.get('version', '')

            # Информация о скриптах
            scripts_info = []
            script_elem = port_element.find('script')
            if script_elem is not None:
                scripts_info.append({
                    'id': script_elem.get('id'),
                    'output': script_elem.get('output', '')
                })

            return {
                'port': int(port_id),
                'protocol': protocol,
                'service': service_name,
                'product': service_product,
                'version': service_version,
                'scripts': scripts_info
            }

        except Exception as e:
            self.logger.error(f"Ошибка парсинга порта: {e}")
            return None

    def create_service_files(self, hosts_data):
        """Создание файлов по типам сервисов"""
        self.logger.info("Создание файлов с результатами по сервисам")
        print(f"\n📁 Создание отчетов...")

        # Группировка по сервисам
        service_groups = defaultdict(list)

        total_ports = sum(len(host['ports']) for host in hosts_data)
        processed_ports = 0

        for host in hosts_data:
            for port_info in host['ports']:
                port = port_info['port']
                service = port_info['service']

                # Определение категории сервиса
                category = self.get_service_category(port, service)

                service_groups[category].append({
                    'host': host['ip'],
                    'hostname': host['hostname'],
                    'port': port,
                    'service': service,
                    'product': port_info['product'],
                    'version': port_info['version']
                })
                
                processed_ports += 1
                progress = (processed_ports / total_ports) * 100 if total_ports > 0 else 0
                print(f"\r   📊 Классификация портов: {processed_ports}/{total_ports} ({progress:.1f}%)", end='', flush=True)

        print()

        # Создание файлов для каждой категории
        categories = list(service_groups.keys())
        total_categories = len(categories)
        
        for i, category in enumerate(categories):
            hosts = service_groups[category]
            if hosts:
                filename = f"{category}_ports.txt"
                filepath = self.reports_dir / filename

                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(f"# {category.upper()} порты\n")
                    f.write(f"# Всего найдено: {len(hosts)}\n")
                    f.write("#" * 50 + "\n\n")

                    for item in hosts:
                        f.write(f"IP: {item['host']}\n")
                        f.write(f"Имя хоста: {item['hostname']}\n")
                        f.write(f"Порт: {item['port']}\n")
                        f.write(f"Сервис: {item['service']}\n")
                        if item['product']:
                            f.write(f"Продукт: {item['product']}\n")
                        if item['version']:
                            f.write(f"Версия: {item['version']}\n")
                        f.write("-" * 30 + "\n")

                print(f"   ✅ Создан {filename} ({len(hosts)} записей)")
                self.logger.info(f"Создан файл: {filename} ({len(hosts)} записей)")

        # Создание общего файла со всеми открытыми портами
        self.create_summary_file(hosts_data)

    def get_service_category(self, port, service_name):
        """Определение категории сервиса по порту и имени"""
        port = int(port)

        # Проверка по известным портам
        for category, ports in self.service_ports.items():
            if port in ports:
                return category

        # Проверка по имени сервиса
        service_name_lower = service_name.lower()

        if any(web in service_name_lower for web in ['http', 'apache', 'nginx', 'iis']):
            return 'web'
        elif 'ssh' in service_name_lower:
            return 'ssh'
        elif 'ftp' in service_name_lower:
            return 'ftp'
        elif 'smtp' in service_name_lower:
            return 'smtp'
        elif 'dns' in service_name_lower:
            return 'dns'
        elif 'mysql' in service_name_lower or 'mariadb' in service_name_lower:
            return 'mysql'
        elif 'postgres' in service_name_lower:
            return 'postgresql'
        elif 'rdp' in service_name_lower or 'remote-desktop' in service_name_lower:
            return 'rdp'
        elif 'vnc' in service_name_lower:
            return 'vnc'
        elif 'smb' in service_name_lower or 'samba' in service_name_lower:
            return 'smb'

        # Если категория не определена
        return 'other'

    def create_summary_file(self, hosts_data):
        """Создание общего файла с результатами"""
        summary_file = self.reports_dir / "all_open_ports.txt"
        
        print(f"   📝 Создание общего отчета...")

        with open(summary_file, 'w', encoding='utf-8') as f:
            f.write("# ОБЩИЙ ОТЧЕТ О СКАНИРОВАНИИ\n")
            f.write(f"# Дата: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("#" * 60 + "\n\n")

            total_hosts = len(hosts_data)
            total_ports = sum(len(host['ports']) for host in hosts_data)

            f.write(f"Всего хостов: {total_hosts}\n")
            f.write(f"Всего открытых портов: {total_ports}\n\n")

            for i, host in enumerate(hosts_data):
                f.write(f"Хост: {host['ip']} ({host['hostname']})\n")

                if host['ports']:
                    for port_info in host['ports']:
                        port_str = f"  {port_info['port']}/{port_info['protocol']}"
                        service_str = f"{port_info['service']}"

                        if port_info['product']:
                            service_str += f" ({port_info['product']}"
                            if port_info['version']:
                                service_str += f" {port_info['version']}"
                            service_str += ")"

                        f.write(f"{port_str:10} {service_str}\n")
                else:
                    f.write("  Нет открытых портов\n")

                f.write("\n")
                
                # Прогресс записи
                progress = ((i + 1) / total_hosts) * 100 if total_hosts > 0 else 0
                print(f"\r   📝 Запись отчета: {i+1}/{total_hosts} хостов ({progress:.1f}%)", end='', flush=True)

        print(f"\n✅ Общий отчет создан")
        self.logger.info(f"Создан общий файл отчета: {summary_file}")

    def generate_html_report(self, xml_file):
        """Генерация HTML отчета из XML"""
        self.logger.info("Генерация HTML отчета")
        print(f"\n🌐 Создание HTML отчета...")

        html_output = self.reports_dir / "scan_report.html"
        xslt_file = "/usr/share/nmap/nmap.xsl"  # Стандартный путь к XSLT в Linux

        # Проверка наличия XSLT файла
        if not os.path.exists(xslt_file):
            self.logger.warning(f"XSLT файл не найден: {xslt_file}")
            self.logger.info("Попытка найти альтернативный XSLT файл...")

            # Поиск альтернативных путей
            alternative_paths = [
                "/usr/local/share/nmap/nmap.xsl",
                "/opt/homebrew/share/nmap/nmap.xsl",  # Для macOS с Homebrew
                "nmap.xsl"  # В текущей директории
            ]

            for path in alternative_paths:
                if os.path.exists(path):
                    xslt_file = path
                    self.logger.info(f"Найден XSLT файл: {xslt_file}")
                    print(f"   🔍 Найден XSLT файл: {xslt_file}")
                    break
            else:
                self.logger.error("XSLT файл не найден. HTML отчет не будет создан.")
                self.logger.info("Установите nmap или укажите путь к nmap.xsl вручную")
                print("   ❌ XSLT файл не найден. Создаю простой отчет...")
                self.create_simple_html_report(xml_file)
                return True

        try:
            # Использование xsltproc для преобразования XML в HTML
            cmd = f"xsltproc -o {html_output} {xslt_file} {xml_file}"
            
            print(f"   ⚙️  Преобразование XML в HTML...")
            self.logger.info(f"Выполняю преобразование: {cmd}")
            
            # Показываем прогресс преобразования
            start_time = time.time()
            result = subprocess.run(
                cmd, 
                shell=True, 
                check=True, 
                capture_output=True, 
                text=True
            )
            
            elapsed = time.time() - start_time
            print(f"   ✅ HTML отчет создан за {elapsed:.1f} секунд")
            self.logger.info("HTML отчет успешно создан")
            return True

        except subprocess.CalledProcessError as e:
            self.logger.error(f"Ошибка при создании HTML отчета: {e}")
            self.logger.error(f"Вывод ошибки: {e.stderr}")
            print(f"   ⚠️  Ошибка при создании HTML отчета. Создаю простую версию...")

            # Попытка создать простой HTML отчет вручную
            self.create_simple_html_report(xml_file)
            return True

        except Exception as e:
            self.logger.error(f"Непредвиденная ошибка: {e}")
            print(f"   ❌ Ошибка при создании отчета: {e}")
            return False

    def create_simple_html_report(self, xml_file):
        """Создание простого HTML отчета вручную"""
        self.logger.info("Создание простого HTML отчета")
        print(f"   🎨 Создание простого HTML отчета...")

        html_output = self.reports_dir / "scan_report_simple.html"
        hosts_data = self.parse_nmap_xml(xml_file)
        
        if not hosts_data:
            print(f"   ❌ Нет данных для отчета")
            return

        html_content = """
        <!DOCTYPE html>
        <html lang="ru">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Nmap Scan Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
                .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                h1 { color: #333; border-bottom: 2px solid #4CAF50; padding-bottom: 10px; }
                h2 { color: #444; margin-top: 30px; }
                .host { background: #f9f9f9; border: 1px solid #ddd; border-radius: 5px; padding: 15px; margin-bottom: 20px; }
                .host-header { background: #4CAF50; color: white; padding: 10px; border-radius: 3px; margin: -15px -15px 15px -15px; }
                .port { margin: 10px 0; padding: 10px; background: white; border-left: 4px solid #2196F3; }
                .open { border-left-color: #4CAF50; }
                .closed { border-left-color: #f44336; }
                .filtered { border-left-color: #ff9800; }
                table { width: 100%; border-collapse: collapse; margin: 20px 0; }
                th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
                th { background-color: #4CAF50; color: white; }
                tr:hover { background-color: #f5f5f5; }
                .summary { background: #e8f5e9; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
                .timestamp { color: #666; font-style: italic; }
                .service-web { background-color: #e3f2fd; }
                .service-ssh { background-color: #f3e5f5; }
                .service-ftp { background-color: #e8f5e8; }
                .progress { background-color: #f1f1f1; border-radius: 5px; margin: 10px 0; }
                .progress-bar { background-color: #4CAF50; height: 20px; border-radius: 5px; text-align: center; color: white; line-height: 20px; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>📡 Отчет сканирования Nmap</h1>
                <div class="timestamp">Сгенерировано: """ + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + """</div>

                <div class="summary">
                    <h2>📊 Статистика</h2>
        """

        # Добавление статистики
        total_hosts = len(hosts_data)
        total_ports = sum(len(host['ports']) for host in hosts_data)
        
        # Подсчет по категориям
        categories = {}
        for host in hosts_data:
            for port_info in host['ports']:
                category = self.get_service_category(port_info['port'], port_info['service'])
                categories[category] = categories.get(category, 0) + 1

        html_content += f"""
                    <p><strong>Всего хостов:</strong> {total_hosts}</p>
                    <p><strong>Всего открытых портов:</strong> {total_ports}</p>
        """
        
        # Добавляем статистику по категориям
        if categories:
            html_content += "<p><strong>Распределение по сервисам:</strong></p><ul>"
            for category, count in sorted(categories.items(), key=lambda x: x[1], reverse=True):
                percentage = (count / total_ports * 100) if total_ports > 0 else 0
                html_content += f"<li>{category}: {count} портов ({percentage:.1f}%)</li>"
            html_content += "</ul>"

        html_content += """
                </div>

                <h2>🎯 Результаты по хостам</h2>
        """

        # Добавление информации о каждом хосте
        for host in hosts_data:
            html_content += f"""
                <div class="host">
                    <div class="host-header">
                        <h3>📍 {host['ip']} ({host['hostname']})</h3>
                    </div>
            """

            if host['ports']:
                html_content += """
                    <table>
                        <thead>
                            <tr>
                                <th>Порт</th>
                                <th>Протокол</th>
                                <th>Сервис</th>
                                <th>Продукт</th>
                                <th>Версия</th>
                                <th>Категория</th>
                            </tr>
                        </thead>
                        <tbody>
                """

                for port_info in host['ports']:
                    category = self.get_service_category(port_info['port'], port_info['service'])
                    service_class = f"service-{category}"
                    html_content += f"""
                            <tr class="{service_class}">
                                <td><strong>{port_info['port']}</strong></td>
                                <td>{port_info['protocol']}</td>
                                <td>{port_info['service']}</td>
                                <td>{port_info['product']}</td>
                                <td>{port_info['version']}</td>
                                <td><span class="category">{category}</span></td>
                            </tr>
                    """

                html_content += """
                        </tbody>
                    </table>
                """
            else:
                html_content += "<p>🔒 Нет открытых портов</p>"

            html_content += "</div>"

        html_content += """
            </div>
        </body>
        </html>
        """

        with open(html_output, 'w', encoding='utf-8') as f:
            f.write(html_content)

        print(f"   ✅ Простой HTML отчет создан")
        self.logger.info(f"Создан простой HTML отчет: {html_output}")

    def run(self, target):
        """Основной метод запуска сканирования и анализа"""
        self.logger.info(f"Запуск сканирования цели: {target}")
        
        print(f"\n{'='*60}")
        print(f"🚀 ЗАПУСК СКАНИРОВАНИЯ NMAP")
        print(f"{'='*60}")
        print(f"Цель: {target}")
        print(f"Параметры: {self.nmap_args}")
        print(f"Директория: {self.output_dir}")
        print(f"{'='*60}")

        # Выполнение сканирования
        xml_file = self.run_nmap_scan(target)

        if not xml_file or not xml_file.exists():
            self.logger.error("Сканирование не удалось или XML файл не создан")
            print(f"\n❌ Сканирование не удалось")
            return False

        print(f"\n{'='*60}")
        print(f"📊 АНАЛИЗ РЕЗУЛЬТАТОВ")
        print(f"{'='*60}")

        # Парсинг результатов
        hosts_data = self.parse_nmap_xml(xml_file)

        if not hosts_data:
            self.logger.warning("Нет данных для анализа")
            print(f"\n⚠️  Нет открытых портов для анализа")
            return False

        # Создание файлов по сервисам
        self.create_service_files(hosts_data)

        # Генерация HTML отчета
        self.generate_html_report(xml_file)

        print(f"\n{'='*60}")
        print(f"✅ АНАЛИЗ ЗАВЕРШЕН УСПЕШНО!")
        print(f"{'='*60}")
        self.logger.info("Анализ завершен успешно!")
        self.print_summary()

        return True

    def print_summary(self):
        """Вывод сводки по результатам"""
        print(f"\n📋 СВОДКА РЕЗУЛЬТАТОВ")
        print(f"{'='*60}")
        print(f"📁 Директория с результатами: {self.output_dir}")
        print(f"📝 Логи: {self.logs_dir}")
        print(f"📄 Отчеты: {self.reports_dir}")
        print(f"\n📊 Созданные файлы:")
        
        files = list(self.reports_dir.iterdir())
        if files:
            for i, file in enumerate(files, 1):
                if file.is_file():
                    size_kb = file.stat().st_size / 1024
                    print(f"   {i:2d}. {file.name:30} ({size_kb:.1f} KB)")
        else:
            print("   ❌ Файлы не найдены")
        
        print(f"\n💡 Совет: Откройте {self.reports_dir}/scan_report.html в браузере")
        print(f"          для просмотра результатов в удобном формате")
        print(f"{'='*60}")

def main():
    parser = argparse.ArgumentParser(
        description='Nmap Scan Analyzer - автоматизирует сканирование и анализ результатов Nmap',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры использования:
  %(prog)s 192.168.1.1 -D scan_results
  %(prog)s 192.168.0.0/24 -D network_scan -n "-sS -sV -p 1-1000"
  %(prog)s scanme.nmap.org -D internet_scan -n "-sC -sV --top-ports 1000"

ВАЖНО: Используйте -p- (все порты) только для одиночных хостов.
Для сетей используйте --top-ports N или конкретные диапазоны портов.
        """
    )

    parser.add_argument('target', help='Цель сканирования (IP, диапазон или домен)')
    parser.add_argument('-D', '--directory', required=True,
                       help='Имя директории для сохранения результатов')
    parser.add_argument('-n', '--nmap-args',
                       default='-sV --top-ports 100',
                       help='Аргументы для Nmap (по умолчанию: -sV --top-ports 100)')

    args = parser.parse_args()

    # Создание экземпляра сканера
    scanner = NmapScanner(args.directory, args.nmap_args)

    # Запуск сканирования
    success = scanner.run(args.target)

    if success:
        print(f"\n🎉 ВСЕ ОПЕРАЦИИ УСПЕШНО ЗАВЕРШЕНЫ!")
        print(f"📁 Результаты сохранены в: {args.directory}")
        sys.exit(0)
    else:
        print(f"\n⚠️  СКАНИРОВАНИЕ ЗАВЕРШИЛОСЬ С ОШИБКАМИ ИЛИ ПРЕРВАНО")
        print(f"📁 Проверьте логи в: {args.directory}/logs/")
        sys.exit(1)

if __name__ == "__main__":
    # Проверка наличия nmap
    if shutil.which("nmap") is None:
        print("❌ Ошибка: Nmap не установлен или не найден в PATH")
        print("Установите Nmap для использования этого скрипта")
        print("Ubuntu/Debian: sudo apt-get install nmap")
        print("CentOS/RHEL: sudo yum install nmap")
        print("macOS: brew install nmap")
        sys.exit(1)

    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n🛑 Программа прервана пользователем")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Непредвиденная ошибка: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
