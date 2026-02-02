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
        
        # Обработчик для консоли
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
        
        self.logger.info(f"Инициализирован сканер. Директория: {self.output_dir}")
        self.logger.info(f"Аргументы Nmap: {self.nmap_args}")
    
    def run_nmap_scan(self, target):
            """Выполнение сканирования Nmap"""
            self.logger.info(f"Начинаю сканирование цели: {target}")
            
            # Имена файлов для результатов
            xml_output = self.reports_dir / "scan_results.xml"
            normal_output = self.reports_dir / "scan_results.txt"
            
            # Команда для выполнения сканирования
            cmd = f"nmap {self.nmap_args} -oX {xml_output} -oN {normal_output} {target}"
            
            self.logger.info(f"Выполняю команду: {cmd}")
            
            # Добавим обработку KeyboardInterrupt в основном блоке
            try:
                # Выполнение команды с захватом вывода
                result = subprocess.run(
                    cmd,
                    shell=True,
                    check=True,
                    capture_output=True,
                    text=True,
                    encoding='utf-8'
                )
                
                self.logger.info("Сканирование успешно завершено")
                self.logger.info(f"STDOUT: {result.stdout[:500]}...")  # Первые 500 символов
                if result.stderr:
                    self.logger.warning(f"STDERR: {result.stderr}")
                
                return xml_output
                
            except KeyboardInterrupt:
                # Пользователь прервал выполнение
                self.logger.warning("Сканирование прервано пользователем")
                print("\n⚠️  Сканирование прервано пользователем")
                print("📁 Частичные результаты могут быть сохранены в:", self.output_dir)
                
                # Проверяем, создались ли файлы
                if xml_output.exists():
                    file_size = xml_output.stat().st_size
                    if file_size > 100:  # Если файл не пустой
                        self.logger.info(f"Частичные результаты сохранены ({file_size} байт)")
                        print(f"✅ Найдены частичные результаты ({file_size} байт)")
                        return xml_output
                
                print("❌ Результаты не найдены или файлы пустые")
                return None
            
            except subprocess.CalledProcessError as e:
                self.logger.error(f"Ошибка выполнения Nmap: {e}")
                self.logger.error(f"Вывод ошибки: {e.stderr}")
                return None
            except Exception as e:
                self.logger.error(f"Непредвиденная ошибка: {e}")
                return None
    
    def parse_nmap_xml(self, xml_file):
        """Парсинг XML вывода Nmap"""
        self.logger.info(f"Парсинг XML файла: {xml_file}")
        
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            hosts_data = []
            
            for host in root.findall('host'):
                host_info = self.parse_host(host)
                if host_info:
                    hosts_data.append(host_info)
            
            self.logger.info(f"Найдено хостов: {len(hosts_data)}")
            return hosts_data
            
        except ET.ParseError as e:
            self.logger.error(f"Ошибка парсинга XML: {e}")
            return []
        except Exception as e:
            self.logger.error(f"Ошибка при обработке XML: {e}")
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
                for port_element in ports_element.findall('port'):
                    port_info = self.parse_port(port_element)
                    if port_info:
                        ports_data.append(port_info)
            
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
        
        # Группировка по сервисам
        service_groups = defaultdict(list)
        
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
        
        # Создание файлов для каждой категории
        for category, hosts in service_groups.items():
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
        
        with open(summary_file, 'w', encoding='utf-8') as f:
            f.write("# ОБЩИЙ ОТЧЕТ О СКАНИРОВАНИИ\n")
            f.write(f"# Дата: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("#" * 60 + "\n\n")
            
            total_hosts = len(hosts_data)
            total_ports = sum(len(host['ports']) for host in hosts_data)
            
            f.write(f"Всего хостов: {total_hosts}\n")
            f.write(f"Всего открытых портов: {total_ports}\n\n")
            
            for host in hosts_data:
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
        
        self.logger.info(f"Создан общий файл отчета: {summary_file}")
    
    def generate_html_report(self, xml_file):
        """Генерация HTML отчета из XML"""
        self.logger.info("Генерация HTML отчета")
        
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
                    break
            else:
                self.logger.error("XSLT файл не найден. HTML отчет не будет создан.")
                self.logger.info("Установите nmap или укажите путь к nmap.xsl вручную")
                return False
        
        try:
            # Использование xsltproc для преобразования XML в HTML
            cmd = f"xsltproc -o {html_output} {xslt_file} {xml_file}"
            
            self.logger.info(f"Выполняю преобразование: {cmd}")
            result = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
            
            self.logger.info("HTML отчет успешно создан")
            return True
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Ошибка при создании HTML отчета: {e}")
            self.logger.error(f"Вывод ошибки: {e.stderr}")
            
            # Попытка создать простой HTML отчет вручную
            self.create_simple_html_report(xml_file)
            return True
            
        except Exception as e:
            self.logger.error(f"Непредвиденная ошибка: {e}")
            return False
    
    def create_simple_html_report(self, xml_file):
        """Создание простого HTML отчета вручную"""
        self.logger.info("Создание простого HTML отчета")
        
        html_output = self.reports_dir / "scan_report_simple.html"
        hosts_data = self.parse_nmap_xml(xml_file)
        
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
        
        html_content += f"""
                    <p><strong>Всего хостов:</strong> {total_hosts}</p>
                    <p><strong>Всего открытых портов:</strong> {total_ports}</p>
        """
        
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
                            </tr>
                        </thead>
                        <tbody>
                """
                
                for port_info in host['ports']:
                    service_class = f"service-{self.get_service_category(port_info['port'], port_info['service'])}"
                    html_content += f"""
                            <tr class="{service_class}">
                                <td><strong>{port_info['port']}</strong></td>
                                <td>{port_info['protocol']}</td>
                                <td>{port_info['service']}</td>
                                <td>{port_info['product']}</td>
                                <td>{port_info['version']}</td>
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
        
        self.logger.info(f"Создан простой HTML отчет: {html_output}")
    
    def run(self, target):
        """Основной метод запуска сканирования и анализа"""
        self.logger.info(f"Запуск сканирования цели: {target}")
        
        # Выполнение сканирования
        xml_file = self.run_nmap_scan(target)
        
        if not xml_file or not xml_file.exists():
            self.logger.error("Сканирование не удалось или XML файл не создан")
            return False
        
        # Парсинг результатов
        hosts_data = self.parse_nmap_xml(xml_file)
        
        if not hosts_data:
            self.logger.warning("Нет данных для анализа")
            return False
        
        # Создание файлов по сервисам
        self.create_service_files(hosts_data)
        
        # Генерация HTML отчета
        self.generate_html_report(xml_file)
        
        self.logger.info("Анализ завершен успешно!")
        self.print_summary()
        
        return True
    
    def print_summary(self):
        """Вывод сводки по результатам"""
        print("\n" + "=" * 60)
        print("СВОДКА ПО РЕЗУЛЬТАТАМ СКАНИРОВАНИЯ")
        print("=" * 60)
        print(f"Директория с результатами: {self.output_dir}")
        print(f"Логи: {self.logs_dir}")
        print(f"Отчеты: {self.reports_dir}")
        print("\nСозданные файлы:")
        
        for file in self.reports_dir.iterdir():
            if file.is_file():
                size_kb = file.stat().st_size / 1024
                print(f"  - {file.name} ({size_kb:.1f} KB)")
        
        print("\n" + "=" * 60)

def main():
    parser = argparse.ArgumentParser(
        description='Nmap Scan Analyzer - автоматизирует сканирование и анализ результатов Nmap',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры использования:
  %(prog)s 192.168.1.1 -D scan_results
  %(prog)s 192.168.0.0/24 -D network_scan -n "-sS -sV -p-"
  %(prog)s scanme.nmap.org -D internet_scan -n "-sC -sV --top-ports 1000"
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
        print(f"\n✅ Сканирование завершено успешно!")
        print(f"📁 Результаты сохранены в: {args.directory}")
        sys.exit(0)
    else:
        print(f"\n❌ Сканирование завершилось с ошибками")
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
    
    main()
