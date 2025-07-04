import os
import mysql.connector
from datetime import datetime

def guardar_deteccion_mysql(url, resultado, probabilidad, tiempo_ms):
    now = datetime.now()
    fecha = now.strftime("%Y-%m-%d")
    hora = now.strftime("%H:%M:%S")

    conn = mysql.connector.connect(
        host="localhost",
        user="root",           # cámbialo si tienes otro usuario
        password="upao",           # o pon tu contraseña real
        database="plugin"
    )

    cursor = conn.cursor()
    sql = '''
        INSERT INTO url_maliciosas (url, resultado, probabilidad, fecha, hora, tiempo_ms)
        VALUES (%s, %s, %s, %s, %s, %s)
    '''
    valores = (url, resultado, probabilidad, fecha, hora, tiempo_ms)
    cursor.execute(sql, valores)
    conn.commit()
    cursor.close()
    conn.close()
