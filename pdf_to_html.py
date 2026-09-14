#!/usr/bin/env python3
"""
Скрипт для обработки PDF отчетов и генерации HTML сводки.
Извлекает данные об уязвимостях из таблиц PDF файлов и создает HTML отчет.
"""

import os
import re
import pdfplumber
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox


def select_folder():
    """Открывает диалоговое окно выбора папки."""
    root = tk.Tk()
    root.withdraw()  # Скрываем главное окно
    root.attributes('-topmost', True)  # Показываем поверх всех окон

    folder_path = filedialog.askdirectory(title="Выберите папку с PDF отчетами")

    root.destroy()
    return folder_path


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
                text = page.extract_text()
                if not text:
                    continue
                
                lines = text.split('\n')
                for line in lines:
                    # Критический уровень (без подозрения)
                    if re.search(r'Критический\s+уровень\s+(?!\(подозрение\))', line, re.IGNORECASE):
                        numbers = re.findall(r'\d+', line)
                        if len(numbers) >= 1:
                            data['critical'] = int(numbers[0])
                    
                    # Критический уровень (подозрение)
                    elif re.search(r'Критический\s+уровень\s+\(подозрение\)', line, re.IGNORECASE):
                        numbers = re.findall(r'\d+', line)
                        if len(numbers) >= 1:
                            data['critical_suspect'] = int(numbers[0])
                    
                    # Высокий уровень (без подозрения)
                    elif re.search(r'Высокий\s+уровень\s+(?!\(подозрение\))', line, re.IGNORECASE):
                        numbers = re.findall(r'\d+', line)
                        if len(numbers) >= 1:
                            data['high'] = int(numbers[0])
                    
                    # Высокий уровень (подозрение)
                    elif re.search(r'Высокий\s+уровень\s+\(подозрение\)', line, re.IGNORECASE):
                        numbers = re.findall(r'\d+', line)
                        if len(numbers) >= 1:
                            data['high_suspect'] = int(numbers[0])
        
        return data, None
    except Exception as e:
        return None, str(e)


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


def generate_html_report(reports, output_path, total_files, processed_files, errors):
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
        .summary {
            background-color: #e7f3ff;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
            border-left: 4px solid #007bff;
        }
        .stats {
            display: inline-block;
            margin-right: 20px;
            padding: 10px 15px;
            background-color: #28a745;
            color: white;
            border-radius: 5px;
        }
        .error-report {
            background-color: #ffe7e7;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
            border-left: 4px solid #dc3545;
        }
        .error-item {
            color: #dc3545;
            margin: 5px 0;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
        }
        th, td {
            padding: 10px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #4CAF50;
            color: white;
        }
        tr:nth-child(even) {
            background-color: #f9f9f9;
        }
        .total-row {
            font-weight: bold;
            background-color: #e9ecef !important;
        }
        .grand-total {
            margin-top: 20px;
            padding: 15px;
            background-color: #fff3cd;
            border-radius: 5px;
            border-left: 4px solid #ffc107;
            font-weight: bold;
        }
    </style>
</head>
<body>
    <h1>📊 Отчет по уязвимостям</h1>
    
    <div class="summary">
        <span class="stats">✅ Обработано файлов: """ + str(processed_files) + """ из """ + str(total_files) + """</span>
"""

    if errors:
        html += """
        <div class="error-report">
            <strong>⚠️ Ошибки при обработке:</strong><br>
"""
        for error in errors:
            html += f'<div class="error-item">• {error}</div>\n'
        html += """
        </div>
"""

    html += """
    </div>
"""

    grand_total_critical = 0
    grand_total_high = 0

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

            html += f"""
                <tr>
                    <td>{segment['cidr']} ({segment['segment_name']})</td>
                    <td>{crit_total}</td>
                    <td>{high_total}</td>
                </tr>
"""

        html += f"""
                <tr class="total-row">
                    <td>Итого по {org_name}</td>
                    <td>{org_data['total_critical']}</td>
                    <td>{org_data['total_high']}</td>
                </tr>
            </tbody>
        </table>
    </div>
"""
        grand_total_critical += org_data['total_critical']
        grand_total_high += org_data['total_high']

    html += f"""
    <div class="grand-total">
        📈 Общий итог:<br>
        Критических уязвимостей: {grand_total_critical}<br>
        Высоких уязвимостей: {grand_total_high}
    </div>
</body>
</html>
"""

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)

    return output_path


def main():
    # Открываем диалог выбора папки
    print("Откройте папку с PDF отчетами...")
    folder_path = select_folder()

    if not folder_path:
        print("Папка не выбрана. Выход.")
        return

    script_dir = Path(folder_path)

    # Находим все PDF файлы
    pdf_files = list(script_dir.glob('*.pdf'))
    total_files = len(pdf_files)

    if total_files == 0:
        messagebox.showwarning("Внимание", "В выбранной папке не найдено PDF файлов.")
        return

    print(f"Найдено PDF файлов: {total_files}")

    reports = []
    errors = []
    processed_files = 0

    for pdf_path in pdf_files:
        print(f"\nОбработка: {pdf_path.name}")

        # Парсим имя файла
        file_info = parse_filename(pdf_path.name)
        if not file_info:
            error_msg = f"Не удалось распарсить имя файла: {pdf_path.name}"
            errors.append(error_msg)
            print(f"  ⚠️ {error_msg}")
            continue

        print(f"  Организация: {file_info['org_name']}")
        print(f"  Сегмент: {file_info['cidr']} ({file_info['segment_name']})")

        # Извлекаем данные из PDF
        vuln_data, error = extract_vulnerability_data(pdf_path)

        if error:
            error_msg = f"Ошибка в обработке файла {pdf_path.name}: {error}"
            errors.append(error_msg)
            print(f"  ❌ {error_msg}")
            continue

        if vuln_data is None:
            error_msg = f"Не удалось извлечь данные из файла: {pdf_path.name}"
            errors.append(error_msg)
            print(f"  ❌ {error_msg}")
            continue

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

        processed_files += 1
        print(f"  ✅ Успешно обработан")

    if reports or errors:
        # Генерируем HTML отчет в той же папке
        output_path = script_dir / 'vulnerability_report.html'
        generate_html_report(reports, output_path, total_files, processed_files, errors)
        print(f"\n✅ Отчет успешно создан: {output_path}")
        print(f"📊 Обработано файлов: {processed_files} из {total_files}")
        
        if errors:
            print(f"\n⚠️ Ошибки при обработке:")
            for error in errors:
                print(f"  - {error}")
        
        # Открываем отчет в браузере
        import webbrowser
        webbrowser.open(str(output_path))
        
        messagebox.showinfo("Завершено", 
                           f"Отчет успешно создан!\n\n"
                           f"Обработано файлов: {processed_files} из {total_files}\n"
                           f"Отчет сохранен: vulnerability_report.html")
    else:
        print("\nНет данных для генерации отчета")


if __name__ == '__main__':
    main()
