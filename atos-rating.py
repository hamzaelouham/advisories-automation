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

    

    
def update_row(row):
     pass

def main():
    initialtime  = time.time()
    filter = str(sys.argv[1])
    
    print()
    log.info('starting process of rating ...!')
    
    execl_name = or 'Redhat-Generated-Month-March.xlsx'
    text_file_name = 'redhat7.txt'

    old_execl = read_execl(execl_name)

    for index, row in old_execl.iterrows():
        for line in read_file(text_file_name):
               if row['RPMs'] == line:
                  log.info('founding Tested package !')
                  print(f'{line} is Tested')
                  
                     
    log.info('successful finishing. Time taken: %.2f seconds' ,time.time() - initialtime)                  


if __name__ == "__main__":
     main()
           

            
