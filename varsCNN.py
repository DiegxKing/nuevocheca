import numpy as np
import pandas as pd

#get data
array_len = 70
df_code = pd.read_csv("encoding.csv")

dic_code={}
for i in range(len(df_code)):
    dic_code[df_code["char"][i]]=df_code["encode"][i]
    
def create_vector(vector):
    new_vector=list(np.zeros(array_len))
    if(len(vector)>=array_len):
        for i in range(array_len):
            new_vector[i]=vector[i]
    else:
        dif=array_len-len(vector)
        for i in range(dif,array_len):
            new_vector[i]=vector[i-dif]
    return new_vector

def encode(char):
    if(char==0):
        char1=0
    else:
        char1=dic_code[char]
    return char1

dic_code[0]=0

def one_hot(char):
    vector=np.zeros(96)
    try:
        vector[dic_code[char]]=vector[dic_code[char]]+1
    except:
        vector[-1]=vector[-1]+1
    return vector

def armarVecCNN(url):
    str_vector = create_vector(url)
    
    oh_matrix = np.zeros((70,96))
    for e in range(70):
        oh_matrix[e] = one_hot(str_vector[e])
     
    dense_v = []
    final_v = np.zeros(96)

    for fila in range(70):
        for e in range(96):
            final_v[e] += oh_matrix[fila][e]    
    #dense_v.append(final_v)
    return final_v
