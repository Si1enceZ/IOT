from pwn import ELF
import os
import pandas as pd
data = {'name':[],'system':[],'strcpy':[],'strncpy':[],'exec':[],'execv':[]}

def search(elf_path):
    global data
    # elf_path = 'elf/timepro.cgi'
    try:
        file = ELF(elf_path)
    except:
        return
    name = elf_path.split('squashfs-root')[-1]
    symbols = file.symbols.keys()
    data['name'].append(name)
    functions = ['system', 'strcpy', 'strncpy', 'exec','execv']

    for function in functions:
        if function in symbols:
            t = 1
        else:
            t = 0
        data[function].append(t)





def traversal(path):
    try:
        directories = os.listdir(path)
    except:
        return
    # print(f'Traversal: {path}')
    for directory in directories:
        if os.path.isdir(path+'\\'+directory):
            traversal(path + '\\' + directory)
        else:
            search(path + '\\' + directory)
    return
traversal(os.getcwd())
df = pd.DataFrame(data)
df.to_csv('output.csv',encoding='utf-8')


