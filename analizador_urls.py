
from openpyxl import Workbook
import os
import time
import requests
import re
import datetime
import argparse

try:
    import requests  
    import openpyxl
    import argparse    #AGREGAR SI PONGO MAS
except ImportError:
    os.system('pip install requests')
    time.sleep(10)
    os.system('pip install openpyxl')
    time.sleep(10)
    os.system('pip install argparse')
    time.sleep(10)
    print("Librerias/modulos importados, ejecuta de nuevo el codigo")
    exit()



def analizar(key, ubicacion):
    wb = Workbook()
    page = wb.active
    page['A1'] = "URL"
    page['B1'] = "Fecha de análisis"  
    page['C1'] = "Total de análisis"
    page['D1'] = "Analisis  positivos"
    page['E1'] = "Clasificación"

    api_key = str(key)
    urls = open(ubicacion, 'r')
    read_urls = urls.read()
    
    api = "https://www.virustotal.com/vtapi/v2/url/report"
    
    pagina_re = re.compile('(https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|www\.[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9]+\.[^\s]{2,}|www\.[a-zA-Z0-9]+\.[^\s]{2,})')
    pagina_e = pagina_re.findall(read_urls)

    for i in range(len(pagina_e)):
        page[f'A{i+2}'] = pagina_e[i]
        page[f'B{i+2}'] = datetime.datetime.now()
        link = pagina_e[i]
        req = requests.get(link)
        
        if req.status_code == 200:
            parametros = {
                'apikey': api_key,
                'resource': link
            }
            analisis = requests.get(api, params=parametros)
            json = analisis.json()
            page[f'C{i+2}'] = json['total']
            page[f'D{i+2}'] = json['positives']
            
            if json['positives'] < 3:
                page[f'E{i+2}'] = "Baja"
            elif json['positives'] >= 3 and json['positives'] < 10:
                page[f'E{i+2}'] = "Media"
            else:
                page[f'E{i+2}'] = "Alta"
        else:
            page[f'A{i+2}'] = "Pagina no encontrada"


    wb.save("D:/Escritorio/Reporte_analizador_urls.xlsx")
    



if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-key', help = 'Api Key')
    parser.add_argument('-ub', help = 'Ubicacion del archivo', default="D:/Escritorio/Programacion/lab7/urls_sospechosas.txt")
    args = parser.parse_args()
    analizar(args.key, args.ub)