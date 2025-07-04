import pandas as pd
import os
import re
import requests
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(BASE_DIR, "words_alpha.txt"), "r") as file:
    english_words_lower_alpha_set = set(word.strip() for word in file.readlines())

# extraer variables para random forest
def preProcessing(link):
    protocol = re.findall('://',link)
    slash_final = re.findall('/$', link)
    
    # anadir :// al principio si no tiene protocolo
    if len(protocol) == 0:
        link = '://' + link   
        
    # si al final no tiene / añadirlo
    if len(slash_final) == 0:
        link = link + '/'
    link_arr = re.findall('//[\w%]+.[\w\W]+?/', link)[0].replace('/','').split('.')
    
    # si no tiene subdominio anadirle www.
    
    if len(link_arr) < 3:
        link = link.replace('://','://www.')
        
    # si termina en "." quitarlo
    if len(re.findall('\.$','link')) > 0:
        link = link[:-1]
    
    return link

def cleanArrayLink(link):
    # obtener un array con los componentes de la url antes del / final   
    link_array = re.findall('[\w]*://[\w\W]+?/', link)[0].replace('://','://.').split('.')
    
    # si no tiene tld anadirle .com
    if len(link_array) < 4:
        link_array[2] = link_array[2].replace('/','')
        link_array.append("com/")
        
    if len(link_array) > 0:
        return link_array
    else:
        return None
    
def getIP(link):
    try:
        IP_address = socket.gethostbyname(link)
    except:
        IP_address = None
    return IP_address

def normalizarAcentos(palabra): # palabra se encuentra como tipo: byte
    a,b = 'áéíóúüñÁÉÍÓÚÜÑ','aeiouunAEIOUUN'
    trans = str.maketrans(a,b)
    
    return str(palabra,'utf-8').translate(trans)

# palabras en ingles
WORDS = english_words_lower_alpha_set 

# palabras en espanol
word_site = "https://raw.githubusercontent.com/JorgeDuenasLerin/diccionario-espanol-txt/master/0_palabras_todas.txt"
response = requests.get(word_site)

PALABRAS = response.content.splitlines()
PALABRAS = [normalizarAcentos(w) for w in PALABRAS]


def armarVecRF(url): 
    vector = []
    url = preProcessing(url)
    split_arr = cleanArrayLink(url)
    

    #attr: subominio, tld, protocolo
    top_level = split_arr[-1].replace('/','')
    protocol = None if split_arr[0] == '://' else 1 if split_arr[0] == 'https://' else 0

    #num caracteres
    patrones = [r'\.',"-","_","=","@","&","!",r"\+",r"\*","#",r"\$","%",r"\?","\d"]
    puntos = len(re.findall(patrones[0],url))
    guiones = len(re.findall(patrones[1],url))
    subguiones = len(re.findall(patrones[2],url))
    iguales = len(re.findall(patrones[3],url))
    arrobas = len(re.findall(patrones[4],url))
    ampersands = len(re.findall(patrones[5],url))
    exclamacion = len(re.findall(patrones[6],url))
    mas = len(re.findall(patrones[7],url))
    asterisco = len(re.findall(patrones[8],url))
    numeral = len(re.findall(patrones[9],url))
    dolar = len(re.findall(patrones[10],url))
    porcentaje = len(re.findall(patrones[11],url))
    interrogacion = len(re.findall(patrones[12],url))
    digitos = len(re.findall(patrones[13],url))

    vector.extend([protocol, puntos, guiones, subguiones, iguales, arrobas, ampersands, exclamacion, mas, asterisco, numeral, dolar, porcentaje, interrogacion,  digitos])
    
    # REVISAR PALBRAS
    palabras = re.findall("[\w]+",url)
    num_eng = sum([1 if w in WORDS else 0 for w in palabras])
    num_esp = sum([1 if w in PALABRAS else 0 for w in palabras])
    num_no_dic = len(palabras) - num_eng - num_esp
    
    # TAMAnO DEL LINK
    size = len(url) 

    #TOP LEVEL DOMAIN
    tld_size = len(str(top_level))
    tld_num = len(re.findall("\d",str(top_level)))

    vector.extend([num_eng, num_esp, num_no_dic, len(url), tld_size, tld_num])
    
    return vector
#print(armarVecRF("https://www.google.com/search?q=visual+studio+code+shortcut+for+run&rlz=1C1CHBF_esPE917PE917&oq=visual+studio+code+shortcut+for+run&aqs=chrome..69i57j0i19i22i30l6.11953j0j7&sourceid=chrome&ie=UTF-8"))