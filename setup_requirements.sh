#!/bin/bash

echo "Установка Nmap Scan Analyzer"
echo "============================"

# Проверка Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 не установлен"
    exit 1
fi

# Установка системных зависимостей
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    # Linux
    if command -v apt-get &> /dev/null; then
        echo "📦 Установка зависимостей для Debian/Ubuntu..."
        sudo apt-get update
        sudo apt-get install -y nmap xsltproc
    elif command -v yum &> /dev/null; then
        echo "📦 Установка зависимостей для CentOS/RHEL..."
        sudo yum install -y nmap libxslt
    fi
elif [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS
    echo "📦 Установка зависимостей для macOS..."
    brew install nmap libxslt
fi

# Назначение прав
chmod +x nmap_scanner.py
chmod +x setup.sh

# Проверка установки
if command -v nmap &> /dev/null; then
    echo "✅ Nmap установлен"
else
    echo "❌ Nmap не установлен"
    exit 1
fi

if command -v xsltproc &> /dev/null; then
    echo "✅ xsltproc установлен"
else
    echo "⚠️  xsltproc не установлен, HTML отчеты будут ограничены"
fi

echo ""
echo "✅ Установка завершена!"
echo ""
echo "Использование:"
echo "./nmap_scanner.py <цель> -D <директория>"
echo ""
echo "Пример:"
echo "./nmap_scanner.py 192.168.1.1 -D my_scan"
