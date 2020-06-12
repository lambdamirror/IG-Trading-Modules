# -*- coding: utf-8 -*-
"""
Created on Sat Mar 24 00:16:07 2020

@author: tranl
"""
import time, os
import threading
import json

from igpy import Client, LSClient
from ultilities import barstr, timestr
start_time = time.time()

"""LSClient functions : Change this to handle opening, closing and message differently"""
def on_message(message):
    '''
    For handling message
    '''
    print(mess)

def on_open():
    '''
    For opening stream
    '''
    pass

def on_close():
    '''
    For closing stream
    '''
    pass

"""Data streaming function : Declare LSClient here"""
def data_stream():
    # data-stream params
    run_time = 10 #seconds
    adapter_set = ''
    subscriptions = {}
    subscriptions['mode'] = 'MERGE'
    subscriptions['item_names'] = ['CHART:IX.D.SPTRD.IFA.IP:1MINUTE']
    subscriptions['field_names'] = ['UTM', 'OFR_OPEN', 'OFR_HIGH', 'OFR_LOW', 'OFR_CLOSE']
    try:
        lightstreamer = LSClient(igclient=client, subscriptions=subscriptions, adapter_set=adapter_set)
        lightstreamer.open_stream(on_open=None)
        while time.time() - start_time < run_time:
            lightstreamer.handle_response(enablePrint=True, on_message=None)
        lightstreamer.close_stream(on_close=None)
    except:
        print('\tFAIL to start data stream. \n')
        pass

def header_print(client):
    '''
    Print Local Time, Timezone and Account Balance Info
    '''
    t_local = time.time()*1000
    print('\n' + barstr(text="", space_size=0))
    print(barstr(text='IG Server Connecting Session Info'))
    print('\n\n\tDemo Server: %s' % str(demo))
    print('\tLocal Time at Start: %s, \n\tServer Timezone Offset : UTC%+d' % (timestr(t_local), resp['timezoneOffset']))
    print('\n\tAccount Balance info at Start:')
    try:
        accounts = client.account_details()['accounts']
        for n in range(len(accounts)):
            info = {str(key): str(value) for key, value in iter(accounts[0].items())}
            balance = {str(key): str(value) for key, value in iter(accounts[0]['balance'].items())}
            print('\tAccount #{}:'.format(n))
            print("\tId : {accountId:<} \tType : {accountType:<} \tStatus : {status:<} \tCurrency : {currency:<}".format(**info))
            print("\tBalance \tTotal : {balance:<} \tAvailable : {available:<}".format(**balance))
        print('\n')
    except Exception:
         print('\tFAIL to connect to client.balance. \n')

"""Personal Account Info"""
demo = True
if demo:
    # demo IG
    username = ''
    password = ''
    apikey = ''
else:
    # IG
    username = ''
    password = ''
    apikey = ''

"""Client to connect to IG Server"""
client = Client(username=username, password=password, api_key=apikey, demo=demo)
resp = client.create_session(encrypted=True)

header_print(client)

"""Multi-threading function. One can call data_stream() directly"""
t1 = threading.Thread(target=data_stream)  
t1.setDaemon(True)      
t1.start()
t1.join()

print('\n\tLocal Time at Close: %s \n' % timestr(time.time()*1000))
print(barstr(text='Elapsed time = {} seconds'.format(round(time.time()-start_time,2))))
print(barstr(text="", space_size=0))
os._exit(1)