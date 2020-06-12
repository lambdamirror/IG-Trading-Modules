# -*- coding: utf-8 -*-
"""
Created on Sat May 16 00:16:07 2020

@author: tranl

CREDIT: LSClient class takes many refrences from 

        - IG lightstreamer example for python: https://github.com/Lightstreamer/Lightstreamer-example-StockList-client-python
        - IG trade: https://github.com/maroxe/igtrade

"""

import requests
import urllib
import json
import base64

from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from ultilities import ig_time_format, barstr, timestr


#%%%%
class Client:
    """
    
    Client class to connect to IG Server (LIVE and DEMO). This script implement most of the common methods, including:
    
        - Account Info : account details, account setting, account acivities/transactions history
        - Market Info : keyword search, epic info, epic prices
        - Positions : create, confirm, update, cancel positions
        - Working Order : create, confirm, update, cancel working orders
        
    For more information about IG REST api: https://labs.ig.com/rest-trading-api-reference
    
    """
    def __init__(self,
                 username:str,
                 password: str,
                 api_key: str,
                 proxies : str ='',
                 demo: bool = False):
        '''
        In any case you must give your username, password and  API key to work with Client
        
        To use DEMO IG account  -> demo = True
        '''
        self.username = username
        self.password = password
        self.api_key = api_key
        self.proxies = proxies
        self.headers = {'content-type': 'application/json; charset=UTF-8', 'Accept': 'application/json; charset=UTF-8', 'X-IG-API-KEY': api_key}
        self.clientId = None
        self.account = None

        if demo == True:
            self.http_way = 'https://demo-api.ig.com/gateway/deal/'
        else:
            self.http_way = 'https://api.ig.com/gateway/deal/'
        self.wss_way = ''    

    def create_session(self, encrypted=False):
        '''
        Create a connecting session to IG Server
        
        Call this function right after declaring the Client class
        '''
        headers = None
        payload = {'identifier': self.username, 'password': self.password}
        if encrypted:
            headers = {'Version': str(2)}
            r0 = self._get_request('session/encryptionKey')
            decoded = base64.b64decode(r0['encryptionKey'])
            key = RSA.importKey(decoded)
            cipher = PKCS1_v1_5.new(key)
            message = self.password + '|' + str(r0['timeStamp'])
            enc = cipher.encrypt(base64.b64encode(message.encode()))           
            encryptedPassword = base64.b64encode(enc).decode()
            self.password = encryptedPassword
            payload['password'] = encryptedPassword
            payload['encryptedPassword'] = 'true'
            
        r = requests.post(  self.request_url(req='session'), 
                            data=json.dumps(payload), 
                            headers=self.request_header(req=headers))
        try:
            self.headers['CST'] = r.headers['cst']
            self.headers['X-SECURITY-TOKEN'] = r.headers['x-security-token']
            body = r.json()
            self.clientId = body[u'clientId']
            self.accounts = body[u'accounts']
            self.wss_way = body[u'lightstreamerEndpoint']
            return body
        except:
            return r
    
    '''
    Implied requets functions
    '''
    def _get_request(self, req, headers=None):
        r = requests.get(self.request_url(req=req),
                         headers=self.request_header(req=headers))
        try:
            return r.json()
        except: 
            return r
    
    def _post_request(self, req, body, headers=None):
        r = requests.post( self.request_url(req=req),
                           data=json.dumps(body),
                           headers=self.request_header(req=headers) )
        try:
            return r.json()
        except:         
            return r

    def _delete_request(self, req, headers=None):
        r = requests.delete( self.request_url(req=req),
                             headers=self.request_header(req=headers) )
        try:
            return r.json()
        except:         
            return r

    def _put_request(self, req, body, headers=None):
        r = requests.put( self.request_url(req=req),
                          data=json.dumps(body),
                          headers=self.request_header(req=headers) )
        try:
            return r.json()
        except:
            return r

    def request_header(self, req=None):
        h = self.headers.copy()
        if req is not None:
            h.update(req)
        return h

    def request_url(self, req, http_way=None):
        return urllib.parse.urljoin(self.http_way or http_way, req)
    
    ''' 
    REST api methods for Account Info
    '''
    def account_details(self):
        return self._get_request('accounts')

    def account_setting(self):
        return self._get_request('accounts/preferences')

    def account_setting_update(self, trailingStop='false'):
        req = 'accounts/preferences'
        body = {'trailingStopsEnabled': trailingStop}
        return self._put_request(req, body)

    def switch_account(self, accountId, setDefault='false'):
        req = 'session'
        body = { "accountId": str(accountId), "defaultAccount": str(setDefault) }
        return self._put_request(req, body)

    def account_activity(self, startTime, endTime, detailed=None, dealId=None, fiql=None, pageSize=None):
        req = f'history/activity?from={ig_time_format(startTime)}&to={ig_time_format(endTime)}'
        querystring = {}
        if bool(detailed): querystring['detailed'] = str(detailed)
        if bool(dealId): querystring['dealId'] = dealId
        if bool(fiql): querystring['filter'] = fiql
        if bool(pageSize): querystring['pageSize'] = pageSize
        req += urllib.parse.urlencode(querystring)
        return self._get_request(req, headers={'Version': str(3)})

    def account_transaction( self, 
                             transactionType=None, 
                             startTime=None,
                             endTime=None, 
                             period=None, 
                             pageSize=None, 
                             pageNum=None ):
        req = 'history/transactions?'
        querystring = {}
        if bool(transactionType): querystring['transactionType'] = transactionType
        if bool(startTime): querystring['from'] = ig_time_format(startTime, encoded=False)
        if bool(endTime): querystring['to'] = ig_time_format(endTime, encoded=False)
        if bool(period): querystring['maxSpanSeconds '] = period
        if bool(pageSize): querystring['pageSize'] = pageSize
        if bool(pageNum): querystring['pageNumber'] = pageNum
        req += urllib.parse.urlencode(querystring)
        return self._get_request(req, headers={'Version': str(2)})

    ''' 
    REST api methods for Market Info
    '''
    def market_search(self, keyword=''):
        return self._get_request(f'markets?searchTerm={str(keyword)}')

    def market_details(self, epic: str = 'IX.D.SPTRD.IFA.IP'):
        req = f'markets/{str(epic)}'
        return self._get_request(req, headers={'Version': str(3)})

    def market_price(self,
                     epic: str = 'IX.D.SPTRD.IFA.IP',
                     interval: str = 'MINUTE',
                     limit: int = 500,
                     startTime: int = None, #%Y %m %d %H:%M:%S
                     endTime: int = None ):
        req = f'prices/{epic}/?resolution={interval}&max={limit}'
        if bool(startTime) and bool(endTime):
            req = f'prices/{epic}?resolution={interval}&from={ig_time_format(startTime)}&to={ig_time_format(endTime)}'
        return self._get_request(req, headers={'Version': str(3)})

    ''' 
    REST api methods for Positions
    '''
    def positions_info(self, dealId=None):
        if dealId is None: req = 'positions'
        else: req = f'positions/{dealId}'
        return self._get_request(req, headers={'Version': str(2)})

    def new_position(   self,        
                        epic : str,                     
                        side : str,
                        orderType : str,
                        quantity : float,
                        price : float = None,
                        timeInForce : str = 'EXECUTE_AND_ELIMINATE',
                        expiry : str = '-',
                        stopLevel : float = None,
                        stopDistance : float = None,
                        limitLevel : float = None,
                        limitDistance : float = None,
                        trailingStopIncrement : float = None,
                        currencyCode : str = 'AUD',
                        quoteId : str = None    ):
        req = 'positions/otc'
        body = { "epic" : epic,                
                 "direction" : side,
                 "size" : str(quantity),
                 "orderType" : orderType,
                 "timeInForce" : timeInForce,
                 "expiry" : expiry,
                 "currencyCode" : currencyCode }
        if orderType!='MARKET': 
            body['level'] = str(price)
        if orderType=='QUOTE': 
            body['quoteId'] = str(quoteId)
            
        if bool(stopLevel) or bool(stopDistance) or bool(limitLevel) or bool(limitDistance): 
            body["forceOpen"] = "true"
        else: body["forceOpen"] = "false"
        
        if (bool(stopLevel) and not bool(stopDistance)) or (not bool(stopLevel) and bool(stopDistance)): 
            body["guaranteedStop"] = 'true'
        else: body["guaranteedStop"] = 'false'
        
        if bool(trailingStopIncrement):
            body["guaranteedStop"] = 'false'
            body["trailingStop"] = 'true'
            body["trailingStopIncrement"] = str(trailingStopIncrement)
        else:
            body["trailingStop"] = 'false'
        
        if bool(stopLevel) and body["trailingStop"] == 'false': body["stopLevel"] = str(stopLevel)
        elif bool(stopDistance): body["stopDistance"] = str(stopDistance)
        
        if bool(limitLevel): body["limitLevel"] = str(limitLevel)
        elif bool(limitDistance): body["limitDistance"] = str(limitDistance)    

        return self._post_request(req, body, headers={'Version': str(2)})

    def update_position(    self,
                            orderId : str,
                            stopLevel : float = None,
                            limitLevel : float = None,
                            trailingStopDistance : float = None,
                            trailingStopIncrement : float = None    ):
        req = f'positions/otc/{orderId}'
        body = {}
        if bool(trailingStopDistance) and bool(trailingStopIncrement) and bool(stopLevel): 
            body['trailingStop'] = 'true'
            body['trailingStopDistance'] = trailingStopDistance
            body['trailingStopIncrement'] = trailingStopIncrement
        else:
            body['trailingStop'] = 'false'
        if bool(stopLevel): body['stopLevel'] = stopLevel
        if bool(limitLevel): body['limitLevel'] = limitLevel

        return  self._put_request(req, body, headers={'Version': str(2)})

    def trade_confirm(self, dealRef):
        req = f'confirms/{dealRef}'
        return self._get_request(req)

    ''' 
    REST api methods for Working Orders
    '''
    def orders_info(self):
        req = 'workingorders'
        return self._get_request(req, headers={'Version': str(2)})

    def new_order(  self,        
                    epic : str,                     
                    side : str,
                    orderType : str,
                    quantity : float,
                    price : float,
                    timeInForce : str = 'GOOD_TILL_CANCELLED',
                    gtDate: str = None,
                    expiry : str = '-',
                    stopLevel : float = None,
                    stopDistance : float = None,
                    limitLevel : float = None,
                    limitDistance : float = None,
                    currencyCode : str = 'AUD'  ):
        req = 'workingorders/otc'
        body = { "epic" : epic,                
                 "direction" : side,
                 "size" : str(quantity),
                 'level' : str(price),
                 "type" : orderType,
                 "timeInForce" : timeInForce,
                 "expiry" : expiry,
                 "currencyCode" : currencyCode }
        if timeInForce=='GOOD_TILL_DATE': body['goodTillDate'] = gtDate
        
        if (bool(stopLevel) and not bool(stopDistance)) or (not bool(stopLevel) and bool(stopDistance)): 
            body["guaranteedStop"] = 'true'
        else: body["guaranteedStop"] = 'false'

        if bool(stopLevel): body["stopLevel"] = str(stopLevel)
        elif bool(stopDistance): body["stopDistance"] = str(stopDistance)
        
        if bool(limitLevel): body["limitLevel"] = str(limitLevel)
        elif bool(limitDistance): body["limitDistance"] = str(limitDistance) 
        
        return self._post_request(req, body, headers={'Version': str(2)})

    def update_order(   self,
                        orderId : str,
                        orderType : str = None,
                        price : float = None,
                        timeInForce : str = None,
                        gtDate : str = None,
                        stopLevel : float = None,
                        stopDistance : float = None,
                        limitLevel : float = None,
                        limitDistance : float = None    ):
        req = f'workingorders/otc/{orderId}'
        body = {}
        if bool(orderType): body['type'] = orderType
        if bool(price): body['level'] = str(price)  
        if bool(timeInForce): body['timeInForce'] = timeInForce
        if bool(gtDate): body['goodTillDate'] = gtDate
        if bool(stopLevel): body['stopLevel'] = stopLevel
        if bool(stopDistance): body['stopDistance'] = stopDistance
        if bool(limitLevel): body['limitLevel'] = limitLevel
        if bool(limitDistance): body['limitDistance'] = limitDistance
        
        return  self._put_request(req, body, headers={'Version': str(2)})

    def cancel_order(self, orderId):
        req = f'workingorders/otc/{orderId}'
        return self._delete_request(req, headers={'Version': str(2)})

###%%%

class LSClient:
    """
    
    Lightstream Client to receive live update from IG SERVER (LIVE or DEMO). 
    
    To open stream --> self.open_stream()
    
    To close stream --> self.close_stream()
    
    For more information about Streaming Subscriptions: https://labs.ig.com/streaming-api-reference
    
    """
    def __init__(   self,
                    igclient,
                    subscriptions : dict,
                    adapter_set : str = '' ):
        '''
        Pass IG Client class, and subscriptions as a dictionary to LSClient.
        
        ['mode', 'item_names', 'field_names'] are all required in subscriptions.keys()
        '''
        self.base_url = urllib.parse.urlparse(igclient.wss_way)
        self.user = igclient.accounts[0][u'accountId']
        self.password = 'CST-'+igclient.headers['CST']+'|XST-'+igclient.headers['X-SECURITY-TOKEN']
        self.adapter_set = adapter_set
        self.CONNECTION_URL_PATH = "lightstreamer/create_session.txt"
        self.BIND_URL_PATH = "lightstreamer/bind_session.txt"
        self.CONTROL_URL_PATH = "lightstreamer/control.txt"
        self._stream_response = None
        self._session = {}
        self.subscriptions = subscriptions

        self._table_count = 0
        
    @staticmethod    
    def _encode_params(params):
        '''
        Encode the parameter for HTTP POST submissions, but only for non empty values...
        '''
        return urllib.parse.urlencode( dict([(k, v) for (k, v) in iter(params.items()) if v]) ).encode("utf-8")
        
    @staticmethod
    def _call(base_url, url, params):
        '''
        Open a network connection and performs HTTP Post with provided params.
        '''
        url = urllib.parse.urljoin(base_url, url)
        body = LSClient._encode_params(params)
        return urllib.request.urlopen(url, data=body)
    
    @staticmethod
    def _decode_field(s, prev=None):
        '''
        Decode a single field according to the Lightstreamer encoding rules.
            1. Literal '$' is the empty string.
            2. Literal '#' is null (None).
            3. Literal '' indicates unchanged since previous update.
            4. If the string starts with either '$' or '#', but is not length 1,
               trim the first character.

        Returns the decoded Unicode string.
        '''
        if s == '$':
            return u''
        elif s == '#':
            return None
        elif s == '':
            return prev
        elif s[0] in '$#':
            s = s[1:]
        return s
    
    def connect(self):
        '''
        Send Connect request to IG Streaming Server. Save control_url for further controls
        Return server response
        '''
        self._stream_response = self._call( self.base_url.geturl(),
                                            self.CONNECTION_URL_PATH,
                                            {"LS_op2": 'create',
                                             "LS_cid": 'mgQkwtwdysogQz2BJ4Ji kOj2Bg',
                                             "LS_adapter_set": self.adapter_set,
                                             "LS_user": self.user,
                                             "LS_password": self.password})
        resp = self._stream_response.readline().decode("utf-8").rstrip()
        if resp == 'OK':
            while 1:
                next_stream_line = self._stream_response.readline().decode("utf-8").rstrip()
                if next_stream_line:
                    session_key, session_value = next_stream_line.split(":", 1)
                    self._session[session_key] = session_value
                else:
                    break
            self.control_url = urllib.parse.urlparse('//' + self._session['ControlAddress'], scheme=self.base_url[0])
        return resp

    def subcribe(self):
        '''
        Send Subscriptions requests to control_url 
        Return server response
        '''
        self._table_count += 1
        field_names = " ".join(self.subscriptions['field_names'])
        item_names = " ".join(self.subscriptions['item_names'])
        server_response = self._call(   self.control_url.geturl(),
                                        self.CONTROL_URL_PATH,
                                        {"LS_session": self._session['SessionId'],
                                        "LS_Table": str(self._table_count),
                                        "LS_op": 'add',
                                        "LS_data_adapter": self.adapter_set,
                                        "LS_mode": self.subscriptions['mode'],
                                        "LS_schema": field_names,
                                        "LS_id": item_names })
        resp = server_response.readline().decode("utf-8").rstrip()
        return resp

    def open_stream(self, on_open=None):
        '''
        Call self.connect() and self.subcribe()
        Create message tracker --> self._prevResp : dict
        '''
        conn_status = self.connect()
        sub_status = self.subcribe()
        self._prevResp = {}
        for item in self.subscriptions['item_names']:
            self._prevResp[item] = {}
            for field in self.subscriptions['field_names']:
                self._prevResp[item][field] = None
        if conn_status=='OK' and sub_status=='OK':
            if bool(on_open):
                on_open()
            else:
                print('\n' + barstr(text='Start Data Streaming') + '\n')
        else:
            print('\tERROR ~ \tConnect : ', conn_status, 'Subcribe : ', sub_status)

    def handle_response(self, enablePrint=True, on_message=None):
        '''
        Process live message from IG Streaming Server
        Pass fucntion on_message to handle the messages differently
        '''
        line = self._stream_response.readline().decode("utf-8").rstrip()
        if line!='PROBE':
            if not bool(on_message):
                toks = line.rstrip('\r\n').split('|')
                item = self.subscriptions['item_names'][int(toks[0].split(',')[-1]) - 1]
                pstr = {}
                for i in range(len(self.subscriptions['field_names'])):
                    field = self.subscriptions['field_names'][i]                
                    value = LSClient._decode_field(toks[i+1], prev=self._prevResp[item][field])
                    try:
                        if field=='UTM': value = timestr(int(value), end='s')
                    except:
                        pass
                    pstr[field] = value
                self._prevResp[item] = pstr.copy()
                if enablePrint:
                    print("{:<35}".format(item), ''.join(['{:>10} : {:<10}'.format(k, v) for k,v in iter(pstr.items())]))
                pstr['item'] = item
                return pstr
            else:
                return on_message(line)

    def unsubcribe(self, tableId=None):
        '''
        Send Unsubscriptions requests to control_url
        Return server response
        '''
        if not bool(tableId):
            table_list = range(self._table_count)
        elif tableId <= self._table_count:
            table_list = [tableId]
        else:
            table_list = []
        for t in table_list:
            server_response = self._call(   self.control_url.geturl(),
                                            self.CONTROL_URL_PATH,
                                            {"LS_session": self._session['SessionId'],
                                            "LS_Table": str(t),
                                            "LS_op": 'delete'}  )
            resp = server_response.readline().decode("utf-8").rstrip()
            if resp == 'OK':
                return resp
            else:
                return 'Unsubcribe Error'
        
    def disconnect(self):
        '''
        Send Disconnect request to IG Streaming Server
        Return server response
        '''
        server_response = self._call(   self.control_url.geturl(),
                                        self.CONTROL_URL_PATH,
                                         {"LS_session": self._session['SessionId'],
                                          "LS_op": 'destroy' } )
        resp = server_response.readline().decode("utf-8").rstrip()
        if resp == 'OK':
            return resp
        else:
            return 'Unsubcribe Error'  
            
    def close_stream(self, on_close=None):
        '''
        Call self.unsubcribe() and self.disconnect()
        '''
        self.unsubcribe()
        self.disconnect()
        if bool(on_close):
            on_close()
        else:
            print('\n' + barstr(text='Close Data Streaming') + '\n')
        
###%%%        