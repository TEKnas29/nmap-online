from flask import Flask,render_template,request
import nmap
import sqlite3
import os
import socket

app = Flask(__name__)
app.secret_key = os.urandom(24)
scanner = nmap.PortScanner()

@app.route('/',methods=['GET','POST'])
def  index():
 try: 
  if request.method == 'POST':
    search = request.form.get("search",False)
    print("website==========",search)
    if search:
      cip = request.remote_addr
      data = socket.gethostbyname_ex(search)
      ip_addr = data[2][0]
      ports = "21-4444"
    scanner.scan(ip_addr,str(ports),"-A -T4 --script=vulners")
    details = scanner.scaninfo()
    Ip_status = scanner[ip_addr].state()
    port = "Open Ports: "+str(scanner[ip_addr]['tcp'].keys())
    os ="OS: "+scanner[ip_addr]['osmatch'][0]['name'] 
    ports = ports.replace("-",",") 
    for i in range(21,4444):
      try:
        if scanner[ip_addr]['tcp'][i] != None:
         v = str("vulners: "+scanner[ip_addr]['tcp'][i]['script']['vulners'])
      except KeyError:
        pass

    print("*****************DONE*********************")
    return render_template("index.html",se =True,search= search,up = Ip_status,port = port,os =os,v = v,cip=cip) 
  else:
    return render_template("index.html",se = False)
 except:
    return render_template("index.html")

if __name__ == '__main__':
   app.run(debug=True,use_reloader = True)