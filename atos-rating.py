import pandas as pd
import logging
import time
import sys
import os 

# Configure the loggin
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

log = logging.getLogger("logger")


def read_file(filename):
    path = os.path.join('Tested', filename)
    with open(path, 'r') as file:
         for line in file:
            yield line.strip()


def read_execl(filename):
    path = os.path.join("collected", filename)
    return pd.read_excel(path)

    

    
def save(df,f):
    log.info('saving ...!')
    file_name = f'{f}-Tested.xlsx'
    path = os.path.join("Tested", file_name)
    if not os.path.exists("Tested"):
       os.makedirs("Tested")
    df.to_excel(path, index=False) 

def main():
    initialtime  = time.time()
    filter = str(sys.argv[1]) 
    # RHEL 7
    execl_name =  str(sys.argv[2])
    text_file_name = str(sys.argv[3]) 

    log.info('starting process of rating ...!')
   
    old_excel = read_execl(execl_name)
    old_excel = old_excel[old_excel['OS'] == filter]
    tested_rpms = set(read_file(text_file_name))
        # for line in read_file(text_file_name):

    for index, row in old_excel.iterrows():
        if row['RPMs'] in tested_rpms:
            log.info('founding Tested package !')
            old_excel.at[index, 'Tested'] = "YES"
            #   old_excel.at[index, 'Tested'] = "YES"
            print(f'{row["RPMs"]} is Tested')

    save(old_excel, filter)
    log.info('successful finishing. Time taken: %.2f seconds' ,time.time() - initialtime)                  
                  
                     


if __name__ == "__main__":
     main()
           

            
