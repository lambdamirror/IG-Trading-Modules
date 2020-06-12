# -*- coding: utf-8 -*-
"""
Created on Sat Mar 16 00:16:07 2020

@author: tranl
"""

import pandas as pd
import sys
import urllib

from datetime import datetime
from tqdm import tqdm

### IG ultilities function
def ig_time_format(strTime: str, encoded=True):
    t = datetime.strptime(strTime, '%d %m %Y %H:%M:%S').strftime("%Y-%m-%d %H:%M:%S")
    s = t.replace(' ', 'T')
    if encoded:
        return urllib.parse.quote(s)
    else: 
        return s

def ig_market_to_df(marketResp: dict):
    if 'prices' in marketResp:
        prices = marketResp['prices']
    else:
        prices = marketResp
    try:
        all_ins = []
        for p in tqdm(prices):
            new_ins = dict()
            new_ins['_t'] = int(datetime.timestamp(datetime.strptime(p['snapshotTime'], '%Y/%m/%d %H:%M:%S'))*1000)
            new_ins['_v'] = p['lastTradedVolume']
            for ptime in [ 'openPrice', 'closePrice', 'highPrice', 'lowPrice' ]:
                for ptype in ['bid', 'ask', 'lastTraded']:
                    new_ins[ptype+'_'+ptime[0]] = p[ptime][ptype]
            all_ins.append(new_ins)
        return pd.DataFrame(all_ins)
    except:
        return None


### Ultility functions  
def barstr(text, symbol='#', length=100, space_size=5):
    bar_size = int((length-len(text))/2)
    bar = ''.join([symbol]*(bar_size-space_size))
    space = ''.join([' ']*space_size)
    return '{:<}{}{}{}{:>}'.format(bar, space, text, space, bar)
  
def print_(s, file):
    with open(file, "a+") as f: 
        f.write('\n' + str(s)) 
    f.close()
    print(s)
        
def timestr(dateTime: int, end='f'):
    if end=='m': s = pd.to_datetime(dateTime, unit='ms').strftime("%y-%m-%d %H:%M")
    elif end=='s': s = pd.to_datetime(dateTime, unit='ms').strftime("%y-%m-%d %H:%M:%S")
    elif end=='f': s = pd.to_datetime(dateTime, unit='ms').strftime("%y-%m-%d %H:%M:%S:%f")[:-3]
    return s
            
