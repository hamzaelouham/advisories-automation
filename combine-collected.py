from dateutil.relativedelta import relativedelta
from datetime import datetime, timezone
import pandas as pd
import logging
import time
import os 

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
log = logging.getLogger("logger")


def save(df):
    folder = 'collected'
    df_sorted = df.sort_values(by='OS')
    last_month = datetime.now(timezone.utc) - relativedelta(months=1)
    file_name = f'finale-report-Month-{last_month.strftime("%B")}.xlsx'
    path = os.path.join(folder, file_name)
    if not os.path.exists(folder):
       os.makedirs(folder)
    df_sorted.to_excel(path, index=False) 

def combine():
    log.info('Starting process !')
    directory = 'Tested'
    files = os.listdir(os.path.abspath(directory))
    dfs = []  # Create an empty list to store DataFrames

             
    for file in files:
        if file.endswith('.xlsx'):
           df = pd.read_excel(os.path.join(directory, file))
           dfs.append(df)  # Append each DataFrame to the list
    
    return pd.concat(dfs, ignore_index=True)

def main():
    initialtime  = time.time()
    save(combine())
    log.info('finale report generated successful. Time taken: %.2f seconds' ,time.time() - initialtime)



if __name__ == "__main__":
     main()
           
            






