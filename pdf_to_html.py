#!/usr/bin/env python3
"""
Скрипт для обработки PDF отчетов и генерации HTML сводки.
Извлекает данные об уязвимостях из таблиц PDF файлов и создает HTML отчет.
"""

import os
import re
import pdfplumber
from pathlib import Path


def extract_vulnerability_data(pdf_path):
    """Извлекает 4 значения уязвимостей из PDF файла."""
    data = {
        'critical': 0,
        'critical_suspect': 0,
        'high': 0,
        'high_suspect': 0
    }
    
    try:
        with pdfplumber.open(pdf_path) as pdf:
            for page in pdf.pages:
                tables = page.extract_tables()
                for table in tables:
                    for row in table:
                        if not row or len(row) < 3:
                            continue
                        
                        cell_text = str(row[0]) if row[0] else ''
                        
                        # Проверяем наличие заголовка "Уровень" чтобы понять что это нужная таблица
                        if 'Уровень' in cell_text and 'Службы/ПО' in str(row[1]):
                            continue  # Это заголовок таблицы
                        
                        # Извлекаем значения из колонок [1] и [2] (Службы/ПО и Узлы)
                        col1_val = int(row[1]) if row[1] and row[1].isdigit() else 0
                        col2_val = int(row[2]) if row[2] and row[2].isdigit() else 0
                        
                        # Ищем строки с нужными уровнями
                        if 'Критический уровень' in cell_text and '(подозрение)' not in cell_text:
                            data['critical'] = col1_val
                        elif 'Критический уровень (подозрение)' in cell_text:
                            data['critical_suspect'] = col1_val
                        elif 'Высокий уровень' in cell_text and '(подозрение)' not in cell_text:
                            data['high'] = col1_val
                        elif 'Высокий уровень (подозрение)' in cell_text:
                            data['high_suspect'] = col1_val
    except Exception as e:
        print(f"Ошибка при обработке {pdf_path}: {e}")
    
    return data


def parse_filename(filename):
    """Парсит имя файла для извлечения названия организации и сегмента сети."""
    # Шаблон: ООО  Пример(10.1.2.0_24 Сегмент сетевого оборудования)_5.pdf
    pattern = r'(.+?)\(([\d\.]+)_([\d]+)\s+(.+?)\)_.*?\.pdf'
    match = re.match(pattern, filename)
    
    if match:
        org_name = match.group(1).strip()
        ip_base = match.group(2)
        prefix = match.group(3)
        segment_name = match.group(4).strip()
        
        # Формируем CIDR нотацию
        cidr = f"{ip_base}/{prefix}"
        
        return {
            'org_name': org_name,
            'cidr': cidr,
            'segment_name': segment_name
        }
    
    return None


def generate_html_report(reports, output_path):
    """Генерирует HTML отчет на основе извлеченных данных."""
    
    # Группируем по организациям
    orgs = {}
    for report in reports:
        org_name = report['org_name']
        if org_name not in orgs:
            orgs[org_name] = {
                'segments': [],
                'total_critical': 0,
                'total_high': 0
            }
        
        segment_data = {
            'cidr': report['cidr'],
            'segment_name': report['segment_name'],
            'critical': report['data']['critical'],
            'critical_suspect': report['data']['critical_suspect'],
            'high': report['data']['high'],
            'high_suspect': report['data']['high_suspect']
        }
        
        orgs[org_name]['segments'].append(segment_data)
        orgs[org_name]['total_critical'] += report['data']['critical'] + report['data']['critical_suspect']
        orgs[org_name]['total_high'] += report['data']['high'] + report['data']['high_suspect']
    
    html = """<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Отчет по уязвимостям</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 900px;
            margin: 20px auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .org-section {
            background: white;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        h1 {
            color: #333;
            border-bottom: 2px solid #4CAF50;
            padding-bottom: 10px;
        }
        h2 {
            color: #4CAF50;
            margin-top: 0;
        }
        .segment {
            margin: 15px 0;
            padding: 10px;
            background: #f9f9f9;
            border-left: 4px solid #4CAF50;
        }
        .total {
            margin-top: 15px;
            padding: 15px;
            background: #e8f5e9;
            border-radius: 5px;
            font-weight: bold;
        }
        .critical {
            color: #d32f2f;
        }
        .high {
            color: #f57c00;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
        }
        th, td {
            padding: 8px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #4CAF50;
            color: white;
        }
    </style>
</head>
<body>
    <h1>Отчет по уязвимостям</h1>
"""
    
    for org_name, org_data in orgs.items():
        html += f"""
    <div class="org-section">
        <h2>{org_name}</h2>
        <table>
            <thead>
                <tr>
                    <th>Сегмент</th>
                    <th>Критические</th>
                    <th>Высокие</th>
                </tr>
            </thead>
            <tbody>
"""
        for segment in org_data['segments']:
            crit_total = segment['critical'] + segment['critical_suspect']
            high_total = segment['high'] + segment['high_suspect']
            
            crit_detail = f"{segment['critical']} крит. + {segment['critical_suspect']} крит. подозр."
            high_detail = f"{segment['high']} высок. + {segment['high_suspect']} выс. подозр."
            
            html += f"""
                <tr>
                    <td>{segment['cidr']} ({segment['segment_name']})</td>
                    <td class="critical">{crit_total} ({crit_detail})</td>
                    <td class="high">{high_total} ({high_detail})</td>
                </tr>
"""
        
        html += f"""
            </tbody>
        </table>
        <div class="total">
            Итого - {org_data['total_critical']} (крит) {org_data['total_high']} (высок)
        </div>
    </div>
"""
    
    html += """
</body>
</html>
"""
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)
    
    return output_path


def main():
    # Определяем рабочую директорию (где лежит скрипт или текущая)
    script_dir = Path(__file__).parent.resolve()
    
    # Находим все PDF файлы
    pdf_files = list(script_dir.glob('*.pdf'))
    
    if not pdf_files:
        print("PDF файлы не найдены в текущей директории")
        return
    
    print(f"Найдено PDF файлов: {len(pdf_files)}")
    
    reports = []
    
    for pdf_path in pdf_files:
        print(f"\nОбработка: {pdf_path.name}")
        
        # Парсим имя файла
        file_info = parse_filename(pdf_path.name)
        if not file_info:
            print(f"  Не удалось распарсить имя файла: {pdf_path.name}")
            continue
        
        print(f"  Организация: {file_info['org_name']}")
        print(f"  Сегмент: {file_info['cidr']} ({file_info['segment_name']})")
        
        # Извлекаем данные из PDF
        vuln_data = extract_vulnerability_data(pdf_path)
        
        print(f"  Критический: {vuln_data['critical']}")
        print(f"  Критический (подозрение): {vuln_data['critical_suspect']}")
        print(f"  Высокий: {vuln_data['high']}")
        print(f"  Высокий (подозрение): {vuln_data['high_suspect']}")
        
        reports.append({
            'org_name': file_info['org_name'],
            'cidr': file_info['cidr'],
            'segment_name': file_info['segment_name'],
            'data': vuln_data
        })
    
    if reports:
        # Генерируем HTML отчет
        output_path = script_dir / 'vulnerability_report.html'
        generate_html_report(reports, output_path)
        print(f"\n✓ HTML отчет создан: {output_path}")
    else:
        print("\nНет данных для генерации отчета")


if __name__ == '__main__':
    main()
