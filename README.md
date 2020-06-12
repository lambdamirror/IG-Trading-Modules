# IG-Trading-Modules
 
 1/ Client class to connect to IG Server (LIVE and DEMO). This script implement most of the common methods, including:

	- Account Info : account details, account setting, account acivities/transactions history
	- Market Info : keyword search, epic info, epic prices
	- Positions : create, confirm, update, cancel positions
	- Working Order : create, confirm, update, cancel working orders
For more information about IG REST api: https://labs.ig.com/rest-trading-api-reference


2/ Lightstream Client to receive live update from IG SERVER (LIVE or DEMO).

	To open stream --> self.open_stream()

	To close stream --> self.close_stream()

For more information about Streaming Subscriptions: https://labs.ig.com/streaming-api-reference


CREDIT: LSClient class takes many refrences from

    - IG lightstreamer example for python: https://github.com/Lightstreamer/Lightstreamer-example-StockList-client-python
    - IG trade: https://github.com/maroxe/igtrade
