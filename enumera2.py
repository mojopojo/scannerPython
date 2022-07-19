"""
enumera2.py - 2022/06/24

Resume: script para: 1- scanear hosts de la red 
                     2- scanear puertos (tcp/udp) de la red y grabar archivo json

Author: morinigo rodrigo (ing.remz@gmail.com)

"""
import scapy.all as scapy
import json
import nmap
import os

lstHost=scapy.SndRcvList()
nmtcp = nmap.PortScanner()
nmudp = nmap.PortScanner()

class myred:
    def __init__(self,ip,mac,tcp,udp):
        self._ip=ip
        self._mac=mac
        self._tcp=tcp
        self._udp=udp
    @property
    def ip(self):
        return self._ip
    @ip.setter
    def ip(self, ip):
        self._ip = ip
    
    @property
    def mac(self):
        return self._mac 
    @mac.setter
    def mac(self, mac):
        self._mac = mac
    
    @property
    def tcp(self):
        return self._tcp
    @tcp.setter
    def tcp(self, tcp):
        self._tcp = tcp
    @property
    def udp(self):
        return self._udp
    @udp.setter
    def udp(self, udp):
        self._udp = udp

myhost={}
fjson=[]
red = myred("","","","")

#scan host-ports
def scanPorts():
    print("Scanner..")
    lstHost = listaHosts('2')

    for host in lstHost:
        myhost["ip"] = red.ip = host[1].psrc
        myhost["mac"] = red.mac = host[1].hwsrc
        print("\n>>>>>>>>>>>>>>> Host :",red.ip,"MAC:",red.mac,"<<<<<<<<<<<<<<<")
        print("\n")
        nmtcp.scan(hosts=red.ip, arguments='-sS -sV')
        try:
            myhost["tcp"] = red.tcp = ports = list(nmtcp[red.ip]['tcp'].keys())
            fjson.append(myhost)
            ports.sort()
            print("-------------Protocolo TCP ----------------")
            for port in ports:
                print("Nro port:{}: Estado:{}".format(port,nmtcp[red.ip]['tcp'][port]['state']))
                print("Name:",nmtcp[red.ip]['tcp'][port]['name'])
                print("Product_Vers :",nmtcp[red.ip]['tcp'][port]['product']," ",nmtcp[red.ip]['tcp'][port]['version'])
                print("\n°°°°°°°°°°°°°°°°")
        except:
            pass

        nmudp.scan(hosts=red.ip, arguments='-sU')
        try:
            myhost["udp"] = red.udp = lports = list(nmudp[red.ip]['udp'].keys())
            fjson.append(myhost)
            lports.sort()
            print("--------------Protocolo UDP------------------")
            for portu in lports:
                print("Nro port:{}: Estado:{}".format(portu,nmudp[red.ip]['udp'][portu]['state']))
                print("Name:",nmudp[red.ip]['udp'][portu]['name'])
                print("\n°°°°°°°°°°°°°°°°")
        except:
            pass

    savejson(fjson)
    limpiar()

#scan host de red
def listaHosts(param):
    # param:1 only print / param:2 only list
    interfaz = input('> Ingrese Direccion de Red (formato CIDR) >>> : ')
    request = scapy.ARP()

    request.pdst = interfaz
    broadcast = scapy.Ether()
    broadcast.dst = 'ff:ff:ff:ff:ff:ff'

    request_broadcast = broadcast / request
    #envia/recibe paquetes de capa2
    hosts = scapy.srp(request_broadcast, timeout = 1)[0]
    
    if param =='1':
        print("\n")
        for host in hosts:
            try:
                print("Direccion IP: {} -- Direwccion MAC: {}".format(host[1].psrc,host[1].hwsrc))
            except:
                pass
    limpiar()

    if param =='2':
       return hosts

#grabar json file
def savejson(fjson):
    print("\n >>>>>>>>>>>>>>>>>>>>>>>>>>>> Archivo output.json generado.. OK")
    with open('output.json', 'w') as jsonf:
      json.dump(fjson, jsonf)

def salir():
    print("Saliendo...!")
    exit()

def limpiar():
    x = input("\n toque cualquier tecla para continuar...")
    os.system('clear')

def main():
    while True:
        print("\n")
        print("|********************************|")
        print("|**| Modulo ScannerPython     |**|")
        print("|**|         Menu             |**|")
        print("|********************************|")
        print("")
        print("Seleccione una de las siguientes opciones:");
        print("1.- Listar Hosts de la Red")
        print("2.- Ver Hosts-Puerto TCP/UDP con archivo JSON ")
        print("3.- Salir\n")

        opcion = int(input("Opcion: "))

        if opcion == 1:
            listaHosts('1')
        elif opcion == 2:
            scanPorts()
        elif opcion == 3:
            salir()

if __name__ == '__main__':
    main();
