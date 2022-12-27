import sys
from io import open
from itertools import *
import re
import tkinter
from tkinter import *
from tkinter import messagebox
from tkinter import filedialog
import tkinter.font as tkFont
import os

def ejecucion():

    ingresarinterfaz = cuadrouno.get()
    ingresarinterfazh4 = cuadrodos.get()
    idnumber = cuadrotres.get()
    adrednumber = cuadrocuatro.get()
    loopback = cuadrocinco.get()
    nameservice = cuadroseis.get()
    textocore = cuadrosiete.get()
    script = cuadroocho.get()

    if ingresarinterfaz != "" and textocore != "" and script != "":

        textocore = open(textocore, "r")
        listacore = list(map(str.rstrip, textocore))
        textocore.close()

        textoscript = open(script, "r")
        listascript = list(map(str.rstrip, textoscript))
        textoscript.close()

        def version():

            ver = ""
            uno_pruebav = "".join(filter(lambda x: "address-family ipv4 vrf" in x, listacore))
            dos_pruebav = "".join(filter(lambda x: "router static" in x, listacore))

            if uno_pruebav != "":
                ver = "v_uno"
            if dos_pruebav != "":
                ver = "v_dos"

            return ver

        ver_core = version()

        def filtrarbloqueinterfaz():

            """Esta funcion se encarga de filtar unicamente el bloque de la interfaz leyendo todo el txt del core"""

            listabloqueinterfaz = []
            encontrarinterfaz = list(filter(lambda linea: ingresarinterfaz in linea, listacore))
            if encontrarinterfaz != []:
                primerindice = int(listacore.index(encontrarinterfaz[0]))
                for x in range(primerindice, len(listacore)):
                    listabloqueinterfaz.append(listacore[x])
                    if re.findall("!", listacore[x]) and listacore[x] == "!":
                        break

            else:
                messagebox.showinfo("Warning", "The legacy interface was not found")
                exit()

            return listabloqueinterfaz

        b_i = filtrarbloqueinterfaz()
        #print(b_i)

        def extraerdatosinterfaz():

            "Esta funcion se encarga de filtar los datos necesarios dentro del bloque de la interfaz, para construir el script"

            l_int = ["", "", "", "", "", "", "", "", "", "", "", "", ""]

            if ver_core == "v_uno":
                l_int[0] = "".join(filter(lambda x: "ip vrf " in x, b_i)).replace("ip vrf forwarding ", "").strip()
                if l_int[0] == "":
                    l_int[0] = "".join(filter(lambda x: "vrf " in x, b_i)).replace("vrf forwarding ", "").strip()
            if ver_core == "v_dos":
                l_int[0] = "".join(filter(lambda x: "vrf" in x, b_i)).replace("vrf", "").strip()

            for x in b_i:
                if re.findall("secondary", x):
                    ipmask_sec = x.replace("ip address", "").replace("secondary", "").strip().split(" ")
                    l_int[1] = ipmask_sec[0]
                    l_int[2] = ipmask_sec[1]
                    b_i.remove(x)

            ipmask = ""
            if ver_core == "v_uno":
                ipmask = "".join(filter(lambda x: "ip address " in x, b_i)).replace("ip address", "").strip().split(" ")
            if ver_core == "v_dos":
                ipmask = "".join(filter(lambda x: "ipv4 address" in x, b_i)).replace("ipv4 address", "").strip().split(" ")
            if ipmask != ['']:
                l_int[3] = ipmask[0]
                l_int[4] = ipmask[1]

            l_int[5] = "".join(filter(lambda x: "description" in x, b_i)).replace("description", "").strip()

            vlan = ""
            if ver_core == "v_uno":
                vlan = "".join(filter(lambda x: "encapsulation dot1Q" in x, b_i)).strip().split(" ")
            if ver_core == "v_dos":
                vlan = "".join(filter(lambda x: "encapsulation dot1q" in x, b_i)).strip().split(" ")

            if len(vlan) == 3:
                l_int[6] = "".join(vlan[2]).strip()
            if len(vlan) == 5:
                l_int[6] = "".join(vlan[2]).strip()
                l_int[7] = "".join(vlan[4]).strip()

            l_int[8] = "".join(filter(lambda x: "input" in x, b_i)).replace("service-policy input ", "").strip()

            l_int[9] = "".join(filter(lambda x: "output" in x, b_i)).replace("service-policy output ", "").strip()

            updown = "".join(filter(lambda x: "shutdown" in x, b_i)).strip()
            if updown == "shutdown":
                l_int[10] = updown

            l_int[11] = "".join(filter(lambda x: "ipv6" in x, b_i))

            ref = l_int[5]
            if re.search("REF", ref):
                ref_i = re.search("REF", ref).end()
                ref_f = ref_i + 10
                ref = ref[ref_i:ref_f]
                ref = filter(str.isdigit, ref)
                l_int[12] = "".join(list(ref))

            return l_int

        d_i = extraerdatosinterfaz()
        print(d_i)

    ##################################################################################################################

        def filtrarbloquevpn():

            """Esta funcion se encarga de filtar unicamente el bloque de la vpn leyendo todo el txt del core"""

            listabloquevpn = []

            if d_i[0] != "":

                encontrarvpnvrf = []
                if ver_core == "v_uno":
                    encontrarvpnvrf = list(filter(lambda linea: "ip vrf " + d_i[0] in linea, listacore))
                if ver_core == "v_dos":
                    encontrarvpnvrf = list(filter(lambda linea: "vrf " + d_i[0] in linea, listacore))
                if encontrarvpnvrf != []:
                    filtrovpnvrf = "".join(encontrarvpnvrf[0]).strip()
                    if filtrovpnvrf == "ip vrf " + d_i[0] or filtrovpnvrf == "vrf " + d_i[0]:
                        primerindice = int(listacore.index(encontrarvpnvrf[0]))
                        for x in range(primerindice, len(listacore)):
                            listabloquevpn.append(listacore[x])
                            if re.findall("!", listacore[x]) and listacore[x] == "!":
                                break
                        return listabloquevpn

                encontrarvpndef = list(filter(lambda linea: "vrf definition " + d_i[0] in linea, listacore))
                if encontrarvpndef != []:
                    filtrovpndef = "".join(encontrarvpndef[0]).strip()
                    if filtrovpndef == "vrf definition " + d_i[0]:
                        primerindice = int(listacore.index(encontrarvpndef[0]))
                        for x in range(primerindice, len(listacore)):
                            listabloquevpn.append(listacore[x])
                            if re.findall("!", listacore[x]):
                                break
            return listabloquevpn

        bloquevpn = filtrarbloquevpn()
        #print(bloquevpn)

        def extraerdatosvpn():

            """Esta funcion es para sacar los datos de la vpn que me interesan para crear la la vpn en el nuevo script """

            l_exp = []
            l_imp = []
            listart = ["", "", "", "", ""]

            if bloquevpn != []:

                if ver_core == "v_uno":

                    listart[0] = "".join(filter(lambda x: "rd" in x, bloquevpn)).replace("rd ", "").strip()

                    listart[1] = "".join(filter(lambda x: "route-target export" in x, bloquevpn)).\
                                replace("route-target export", "").strip().split(" ")
                    listart[1] = [x for x in listart[1] if x != ""]

                    listart[2] = "".join(filter(lambda x: "route-target import" in x, bloquevpn)).\
                                replace("route-target import", "").strip().split(" ")
                    listart[2] = [x for x in listart[2] if x != ""]

                    listart[3] = "".join(filter(lambda x: "description" in x, bloquevpn)). \
                                    replace("description ", "").strip()

                    listart[4] = "".join(filter(lambda x: "map" in x, bloquevpn)).strip()

                if ver_core == "v_dos":

                    r_ext = "".join(filter(lambda x: "export route-target" in x, bloquevpn))
                    if r_ext != "":
                        i_ext = int(bloquevpn.index(r_ext))
                        for x in range(i_ext, len(bloquevpn)):
                            l_exp.append(bloquevpn[x])
                            if re.findall("!", bloquevpn[x]):
                                break
                        l_exp.remove(l_exp[0])
                        l_exp.pop()
                        listart[1] = "".join(l_exp).strip().split(" ")
                        listart[1] = [x for x in listart[1] if x != ""]

                    r_imp = "".join(filter(lambda x: "import route-target" in x, bloquevpn))
                    if r_imp != "":
                        i_imp = int(bloquevpn.index(r_imp))
                        for x in range(i_imp, len(bloquevpn)):
                            l_imp.append(bloquevpn[x])
                            if re.findall("!", bloquevpn[x]):
                                break
                        l_imp.remove(l_imp[0])
                        l_imp.pop()
                        listart[2] = "".join(l_imp).strip().split(" ")
                        listart[2] = [x for x in listart[2] if x != ""]

                    listart[3] = "".join(filter(lambda x: "description" in x, bloquevpn)). \
                                    replace("description ", "").strip()

            return listart

        datosvpn = extraerdatosvpn()
        #print(datosvpn)

    ################################################################################################################

        def bgpall():

            l_bgp_all = []
            i_bgp = "".join((filter(lambda x: "router bgp " in x, listacore)))
            num_uno = int(listacore.index(i_bgp))
            for x in range(num_uno, len(listacore)):
                l_bgp_all.append(listacore[x])
                if re.findall("!", listacore[x]) and listacore[x] == "!":
                    break

            return l_bgp_all

        l_bgp_all = bgpall()

        def filtrarbloquebgp():

            listabloquebgp = []

            if d_i[0] != "":

                encontrarpeer = list(filter(lambda x: "vrf " + d_i[0] in x, l_bgp_all))
                if encontrarpeer != []:
                    filtropeer = "".join(encontrarpeer[0]).strip()
                    if filtropeer == "address-family ipv4 vrf " + d_i[0] or filtropeer == "vrf " + d_i[0]:
                        primerindice = int(l_bgp_all.index(encontrarpeer[0]))
                        for x in range(primerindice, len(l_bgp_all)):
                            listabloquebgp.append(l_bgp_all[x])
                            if ver_core == "v_uno":
                                if re.findall("!", l_bgp_all[x]):
                                    break
                            if ver_core == "v_dos":
                                if l_bgp_all[x] == " !":
                                    break

            return listabloquebgp

        bloquebgp = filtrarbloquebgp()
        #print(bloquebgp)

        def filtrarbloquerutas():

            l_r_all = []
            l_r_info = []
            l_r_vpn = []
            encontrarrutas = []
            primerindice = ""

            if ver_core == "v_uno":
                encontrarrutas = list(filter(lambda x: "ip route " in x, listacore))
                if encontrarrutas != []:
                    primerindice = int(listacore.index(encontrarrutas[0]))
                    for x in range(primerindice, len(listacore)):
                        l_r_all.append(listacore[x])
                        if re.findall("!", listacore[x]):
                            break

            if ver_core == "v_dos":

                encontrarrutas = list(filter(lambda x: "router static" in x, listacore))
                if encontrarrutas != []:
                    primerindice = int(listacore.index(encontrarrutas[0]))
                    for x in range(primerindice, len(listacore)):
                        l_r_all.append(listacore[x])
                        if re.findall("!", listacore[x]) and listacore[x] == "!":
                            break

                    for x in range(primerindice, len(listacore)):
                        l_r_info.append(listacore[x])
                        if re.findall("!", listacore[x]):
                            break

                    find_r_vpn = list(filter(lambda x: "vrf " + d_i[0] in x, l_r_all))
                    if find_r_vpn != []:
                        i_r_vpn = int(l_r_all.index(find_r_vpn[0]))
                        for x in range(i_r_vpn, len(l_r_all)):
                            l_r_vpn.append(l_r_all[x])
                            if re.findall("!", l_r_all[x]):
                                break

            return l_r_all, l_r_info, l_r_vpn

        bloquerutas = filtrarbloquerutas()
        l_r_all = bloquerutas[0]
        l_r_info = bloquerutas[1]
        l_r_vpn = bloquerutas[2]
        #print(bloquerutas)

        def filtrarpeer():
            """Esta funcion busca el peer especifico dentro de todos los posibles peer de la VPN"""

            look_peer = ["", "", "", ""]

            if d_i[3] != "":
                ip_div = d_i[3].split(".")
                ip_div = [int(x) for x in ip_div]

                if d_i[4] == "255.255.255.252":
                    look_peer[0] = "{}.{}.{}.{}".format(ip_div[0], ip_div[1], ip_div[2], (ip_div[3] + 1))
                    look_peer[1] = "{}.{}.{}.{}".format(ip_div[0], ip_div[1], ip_div[2], (ip_div[3] - 1))

                if d_i[4] == "255.255.255.248":
                    look_peer[0] = "{}.{}.{}.{}".format(ip_div[0], ip_div[1], ip_div[2], (ip_div[3] + 5))
                    look_peer[1] = "{}.{}.{}.{}".format(ip_div[0], ip_div[1], ip_div[2], ip_div[3] - 5)
                    look_peer[2] = "{}.{}.{}.{}".format(ip_div[0], ip_div[1], ip_div[2], ip_div[3] + 1)
                    look_peer[3] = "{}.{}.{}.{}".format(ip_div[0], ip_div[1], ip_div[2], ip_div[3] - 1)

            return look_peer

        l_peers = filtrarpeer()
        #print(l_peers)

        def encontrarpeeryrutas():

            l_rutas_tem = []
            l_rutas_fin = []
            l_r_fin = []
            l_peer_ruta = ["", "", "", ""]
            l_p_p = []
            peer = ""

            if d_i[3] != "" and bloquebgp != []:
                if ver_core == "v_uno":
                    for x in bloquebgp:

                        if re.findall(l_peers[0] + " ", x) and l_peers[0] != "":
                            l_p_p.append(x)
                            peer = l_peers[0]
                        if re.findall(l_peers[1] + " ", x) and l_peers[1] != "":
                            l_p_p.append(x)
                            peer = l_peers[1]
                        if re.findall(l_peers[2] + " ", x) and l_peers[2] != "":
                            l_p_p.append(x)
                            peer = l_peers[2]
                        if re.findall(l_peers[3] + " ", x) and l_peers[3] != "":
                            l_p_p.append(x)
                            peer = l_peers[3]

                    for linea in l_r_all:

                        if re.findall(d_i[0], linea) and re.findall(l_peers[0], linea):
                            linea = linea.replace("ip route vrf", "ip route-static vpn-instance")
                            if re.findall("name", linea):
                                linea = linea.replace("name", "description").strip() + " ***"
                            else:
                                linea = linea + " SINDES"
                            l_rutas_tem.append(linea + "\n")
                            l_peer_ruta[0] = l_peers[0]

                        if re.findall(d_i[0], linea) and re.findall(l_peers[1], linea):
                            linea = linea.replace("ip route vrf", "ip route-static vpn-instance")
                            if re.findall("name", linea):
                                linea = linea.replace("name", "description").strip() + " ***"
                            else:
                                linea = linea + " SINDES"
                            l_rutas_tem.append(linea + "\n")
                            l_peer_ruta[1] = l_peers[1]

                        if re.findall(d_i[0], linea) and re.findall(l_peers[2], linea) and l_peers[2] != "":
                            linea = linea.replace("ip route vrf", "ip route-static vpn-instance")
                            if re.findall("name", linea):
                                linea = linea.replace("name", "description").strip() + " ***"
                            else:
                                linea = linea + " SINDES"
                            l_rutas_tem.append(linea + "\n")
                            l_peer_ruta[2] = l_peers[2]

                        if re.findall(d_i[0], linea) and re.findall(l_peers[3], linea) and l_peers[3] != "":
                            linea = linea.replace("ip route vrf", "ip route-static vpn-instance")
                            if re.findall("name", linea):
                                linea = linea.replace("name", "description").strip() + " ***"
                            else:
                                linea = linea + " SINDES"
                            l_rutas_tem.append(linea + "\n")
                            l_peer_ruta[3] = l_peers[3]

                if ver_core == "v_dos":

                    for x in bloquebgp:
                        if re.findall(l_peers[0], x) and l_peers[0] != "":
                            peer = l_peers[0]
                        if re.findall(l_peers[1], x) and l_peers[1] != "":
                            peer = l_peers[1]
                        if re.findall(l_peers[2], x) and l_peers[2] != "":
                            peer = l_peers[2]
                        if re.findall(l_peers[3], x) and l_peers[3] != "":
                            peer = l_peers[3]

                    find_peer = list(filter(lambda x: peer in x, bloquebgp))
                    if find_peer[0] == "  neighbor " + peer:
                        i_nei = int(bloquebgp.index(find_peer[0]))
                        for x in range(i_nei, len(bloquebgp)):
                            l_p_p.append(bloquebgp[x])
                            if re.findall("!", bloquebgp[x]):
                                break

                    for x in l_r_vpn:
                        if re.findall(l_peers[0], x):
                            x = "ip route-static vpn-instance " + d_i[0] + " " + x.replace("/", " ").strip()
                            if re.findall("description", x):
                                x = x + " ***"
                            else:
                                x = x + " SINDES"
                            l_rutas_tem.append(x + "\n")
                            l_peer_ruta[0] = l_peers[0]

                        if re.findall(l_peers[1], x):
                            x = "ip route-static vpn-instance " + d_i[0] + " " + x.replace("/", " ").strip()
                            if re.findall("description", x):
                                x = x + " ***"
                            else:
                                x = x + " SINDES"
                            l_rutas_tem.append(x + "\n")
                            l_peer_ruta[1] = l_peers[1]

                        if re.findall(l_peers[2], x) and l_peers[2] != "":
                            x = "ip route-static vpn-instance " + d_i[0] + " " + x.replace("/", " ").strip()
                            if re.findall("description", x):
                                x = x + " ***"
                            else:
                                x = x + " SINDES"
                            l_rutas_tem.append(x + "\n")
                            l_peer_ruta[2] = l_peers[2]

                        if re.findall(l_peers[3], x) and l_peers[3] != "":
                            x = "ip route-static vpn-instance " + d_i[0] + " " + x.replace("/", " ").strip()
                            if re.findall("description", x):
                                x = x + " ***"
                            else:
                                x = x + " SINDES"
                            l_rutas_tem.append(x + "\n") + " ***"
                            l_peer_ruta[3] = l_peers[3]


            if d_i[3] != "" and d_i[0] == "":

                if ver_core == "v_uno":
                    for linea in l_r_all:

                        if not re.findall("vrf ", linea) and re.findall(l_peers[0], linea):
                            linea = linea.replace("ip route", "ip route-static vpn-instance INFOINTERNET")
                            if re.findall("name", linea):
                                linea = linea.replace("name", "description *** INFOINTERNET").strip() + " ***"
                            else:
                                linea = linea + " SINDES"
                            l_rutas_tem.append(linea + "\n")
                            l_peer_ruta[0] = l_peers[0]

                        if not re.findall("vrf ", linea) and re.findall(l_peers[1], linea):
                            linea = linea.replace("ip route ", "ip route-static vpn-instance INFOINTERNET")
                            if re.findall("name", linea):
                                linea = linea.replace("name", "description *** INFOINTERNET").strip() + " ***"
                            else:
                                linea = linea + " SINDES"
                            l_rutas_tem.append(linea + "\n")
                            l_peer_ruta[1] = l_peers[1]

                        if not re.findall("vrf ", linea) and re.findall(l_peers[2], linea) and l_peers[2] != "":
                            linea = linea.replace("ip route", "ip route-static vpn-instance INFOINTERNET")
                            if re.findall("name", linea):
                                linea = linea.replace("name", "description *** INFOINTERNET").strip() + " ***"
                            else:
                                linea = linea + " SINDES"
                            l_rutas_tem.append(linea + "\n")
                            l_peer_ruta[2] = l_peers[2]

                        if not re.findall("vrf ", linea) and re.findall(l_peers[3], linea) and l_peers[3] != "":
                            linea = linea.replace("ip route ", "ip route-static vpn-instance INFOINTERNET")
                            if re.findall("name", linea):
                                linea = linea.replace("name", "description *** INFOINTERNET").strip() + " ***"
                            else:
                                linea = linea + " SINDES"
                            l_rutas_tem.append(linea + "\n")
                            l_peer_ruta[3] = l_peers[3]

                if ver_core == "v_dos":
                    for x in l_r_info:

                        if re.findall(l_peers[0], x):
                            x = "ip route-static vpn-instance INFOINTERNET " + x.replace("/", " ").strip()
                            if re.findall("description", x):
                                x = x + " ***"
                            else:
                                x = x + " SINDES"
                            l_rutas_tem.append(x + "\n")
                            l_peer_ruta[0] = l_peers[0]

                        if re.findall(l_peers[1], x):
                            x = "ip route-static vpn-instance INFOINTERNET " + x.replace("/", " ").strip()
                            if re.findall("description", x):
                                x = x + " ***"
                            else:
                                x = x + " SINDES"
                            l_rutas_tem.append(x + "\n")
                            l_peer_ruta[1] = l_peers[1]

                        if re.findall(l_peers[2], x) and l_peers[2] != "":
                            x = "ip route-static vpn-instance INFOINTERNET " + x.replace("/", " ").strip()
                            if re.findall("description", x):
                                x = x + " ***"
                            else:
                                x = x + " SINDES"
                            l_rutas_tem.append(x + "\n")
                            l_peer_ruta[2] = l_peers[2]

                        if re.findall(l_peers[3], x) and l_peers[3] != "":
                            x = "ip route-static vpn-instance INFOINTERNET " + x.replace("/", " ").strip()
                            if re.findall("description", x):
                                x = x + " ***"
                            else:
                                x = x + " SINDES"
                            l_rutas_tem.append(x + "\n")
                            l_peer_ruta[3] = l_peers[3]

            for i in l_rutas_tem:
                if re.findall(l_peers[0] + " ", i) and l_peer_ruta[0] != "":
                    l_rutas_fin.append(i)
                if re.findall(l_peers[1] + " ", i) and l_peer_ruta[1] != "":
                    l_rutas_fin.append(i)
                if re.findall(l_peers[2] + " ", i) and l_peer_ruta[2] != "":
                    l_rutas_fin.append(i)
                if re.findall(l_peers[3] + " ", i) and l_peer_ruta[3] != "":
                    l_rutas_fin.append(i)

            find_des = "".join(filter(lambda x: "SINDES" in x, l_rutas_fin))
            for x in l_rutas_fin:
                if find_des != "" and d_i[12] != "":
                    x = x.replace("SINDES", "description REF:" + d_i[12])
                    l_r_fin.append(x)
                elif find_des != "" and d_i[5] == "" and d_i[12] == "":
                    x = x.replace("SINDES", "")
                    l_r_fin.append(x)
                elif find_des != "" and d_i[12] == "" and d_i[5] != "":
                    x = x.replace("SINDES", "description " + d_i[5])
                    l_r_fin.append(x)

            for x in l_rutas_fin:
                if find_des == "":
                    l_r_fin.append(x)

            return [l_p_p, peer, l_r_fin]

        bloquepeeryrutas = encontrarpeeryrutas()
        car_peer = bloquepeeryrutas[0]
        datopeer = bloquepeeryrutas[1]
        datorutas = bloquepeeryrutas[2]

        def atributospeer():

            l_a_peer = [False, 0, False, 0, "", False, 0, False, False, False, 0, "", "", 0, False]

            if bloquebgp != []:

                l_a_peer[0] = True if "".join(filter(lambda x: "redistribute static" in x, bloquebgp)) else False

                mp = "".join(filter(lambda x: "maximum-paths" in x, bloquebgp)).replace("maximum-paths ", "").strip()
                l_a_peer[1] = mp if mp != "" else 0

                l_a_peer[2] = True if "".join(filter(lambda x: "default-information" in x, bloquebgp)) else False

                l_a_peer[14] = True if "".join(filter(lambda x: "redistribute rip" in x, bloquebgp)) else False

                if car_peer != []:

                    ra = "".join(filter(lambda x: "remote-as" in x, car_peer))
                    if ver_core == "v_uno":
                        ra = ra.replace("neighbor " + datopeer + " remote-as", "").strip()
                    if ver_core == "v_dos":
                        ra = ra.replace(" remote-as", "").strip()
                    l_a_peer[3] = ra if ra != "" else 0

                    des = "".join(filter(lambda x: "description" in x, car_peer))
                    if ver_core == "v_uno":
                        des = des.replace("neighbor " + datopeer + " description", "").strip()
                    if ver_core == "v_dos":
                        des = des.replace("description", "").strip()
                    l_a_peer[4] = des if des != "" else ""

                    l_a_peer[5] = True if "".join(filter(lambda x: "soft" in x, car_peer)) else False

                    mpfx = "".join(filter(lambda x: "maximum-prefix" in x, car_peer))
                    if ver_core == "v_uno":
                        mpfx = mpfx.replace("neighbor " + datopeer + " maximum-prefix", "").strip()
                    if ver_core == "v_dos":
                        mpfx = mpfx.replace(" maximum-prefix", "").strip()
                    l_a_peer[6] = mpfx if mpfx != "" else 0

                    l_a_peer[7] = True if "".join(filter(lambda x: "send-community" in x, car_peer)) else False

                    l_a_peer[8] = True if "".join(filter(lambda x: "as-override" in x, car_peer)) else False

                    l_a_peer[9] = True if "".join(filter(lambda x: "password" in x, car_peer)) else False

                    ebgp = "".join(filter(lambda x: "ebgp-multihop " in x, car_peer))
                    if ver_core == "v_uno":
                        ebgp = ebgp.replace("neighbor " + datopeer + " ebgp-multihop", "").strip()
                    if ver_core == "v_dos":
                        ebgp = ebgp.replace("ebgp-multihop", "").strip()
                    l_a_peer[10] = ebgp if ebgp != "" else 0

                    allw = "".join(filter(lambda x: "allowas-in" in x, car_peer))
                    if ver_core == "v_uno":
                        allw = allw.replace("neighbor " + datopeer, "").strip().replace("allowas-in", "allow-as-loop")
                    if ver_core == "v_dos":
                        allw = allw.strip().replace("allowas-in", "allow-as-loop")
                    l_a_peer[11] = allw if allw != "" else ""

                    rrc = "".join(filter(lambda x: "route-reflector-client" in x, car_peer))
                    rrc = rrc.replace("neighbor " + datopeer, "").strip()
                    rrc = rrc.replace("route-reflector-client", "reflect-client")
                    l_a_peer[12] = rrc if rrc != "" else ""

                    ai = "".join(filter(lambda x: "advertisement-interval" in x, car_peer))
                    ai = ai.strip().replace("advertisement-interval", "").strip()
                    l_a_peer[13] = ai if ai != "" else 0

                if ver_core == "v_dos":
                    datosvpn[0] = "".join(filter(lambda x: "rd" in x, bloquebgp)).replace("rd ", "").strip()

            return l_a_peer, datosvpn

        bgp_def = atributospeer()
        l_a_peer = bgp_def[0]
        datosvpn = bgp_def[1]

    ###############################################################################################################

        def filtrarbloquetpe():

            """Esta funcion se encarga de filtar el bloque del traficc policy en caso de tener"""

            valorestpeenlace = []

            if d_i[8] != "":
                encontrarpolicyesp = list(filter(lambda lineatpe: "policy-map " + d_i[8] in lineatpe, listacore))
                if encontrarpolicyesp != []:
                    listabloquetpe = []
                    primerindice = int(listacore.index(encontrarpolicyesp[0]))
                    for x in range(primerindice, len(listacore)):
                        listabloquetpe.append(listacore[x])
                        if re.findall("policy-map", listacore[x]) and x > primerindice:
                            break
                        if re.findall("!", listacore[x]) and listacore[x] == "!":
                            break

                    listabloquetpe.remove(listabloquetpe[0])
                    listabloquetpe.remove(listabloquetpe[len(listabloquetpe) - 1])
                    listabloquetpe = "".join(listabloquetpe)
                    for numeros in listabloquetpe.split():
                        try:
                            valorestpeenlace.append(int(numeros))
                        except ValueError:
                            pass

                    try:
                        primervalor = int(valorestpeenlace[0] / 1000)
                        valorestpeenlace[0] = primervalor
                    except IndexError:
                        valorestpeenlace = ["", "", ""]

                else:
                    print("El policy map no fue encontrado")
                    exit()

            return valorestpeenlace

        bloquetpe = filtrarbloquetpe()
        #print(bloquetpe)

        def filtrarbloquetps():

            sp = ""
            sa = ""
            l_tps = []

            if d_i[9] != "" and d_i[9] != d_i[8]:
                encontrartps = list(filter(lambda lineatps: "policy-map " + d_i[9] in lineatps, listacore))
                if encontrartps != []:
                    listabloquetps = []
                    primerindice = int(listacore.index(encontrartps[0]))
                    for x in range(primerindice, len(listacore)):
                        listabloquetps.append(listacore[x])
                        if re.findall("policy-map", listacore[x]) and x > primerindice:
                            break
                        if re.findall("!", listacore[x]) and listacore[x] == "!":
                            break

                    listabloquetps.remove(listabloquetps[0])
                    listabloquetps.remove(listabloquetps[len(listabloquetps) - 1])
                    l_tps = listabloquetps

                    sa = "".join(filter(lambda x: "shape" in x, l_tps)).replace("shape average", "").strip().split(" ")
                    if sa == ['']:
                        sa = "".join(filter(lambda x: "police cir" in x, l_tps))
                        sa = sa.replace("police cir", "").strip().split(" ")
                    try:
                        sa = int(int(sa[0]) / 1000)
                    except ValueError:
                        sa = "XX"

                    sp = "".join(filter(lambda x: "service-policy" in x, l_tps)).replace("service-policy ", "").strip()

            return [sp, sa]

        bloquetps = filtrarbloquetps()
        print(bloquetps)

        def filtrarbloqueflow():

            listabloqueflowexterna = []
            clasesvalores = []
            clasesnumeros = []
            diccionario = {}

            if bloquetps[0] != "" and bloquetps[1] != "":

                encontrarflow = list(filter(lambda lineaflow: "policy-map " + bloquetps[0] in lineaflow, listacore))
                if encontrarflow != []:
                    listabloqueflow = []
                    primerindice = int(listacore.index(encontrarflow[0]))
                    for x in range(primerindice, len(listacore)):
                        listabloqueflow.append(listacore[x])
                        if re.findall("policy-map", listacore[x]) and x > primerindice:
                            break
                        if re.findall("!", listacore[x]) and listacore[x] == "!":
                            break
                    listabloqueflow.remove(listabloqueflow[0])
                    listabloqueflow.remove(listabloqueflow[len(listabloqueflow) - 1])
                    listabloqueflowexterna = listabloqueflow

                    for clases in listabloqueflowexterna:
                        if re.findall("MM", clases):
                            cambio = clases.replace("class MM", "EF").strip()
                            clasesvalores.append(cambio)
                        if re.findall("ORO", clases):
                            cambio = clases.replace("class ORO", "af2").strip()
                            clasesvalores.append(cambio)
                        if re.findall("PLATA", clases):
                            cambio = clases.replace("class PLATA", "af1").strip()
                            clasesvalores.append(cambio)
                        if re.findall("BRONCE", clases):
                            cambio = clases.replace("class BRONCE", "BE").strip()
                            clasesvalores.append(cambio)
                        if re.findall("PLATINO", clases):
                            cambio = clases.replace("class PLATINO", "af3").strip()
                            clasesvalores.append(cambio)
                        if re.findall("VIDEO", clases):
                            cambio = clases.replace("class VIDEO", "af4").strip()
                            clasesvalores.append(cambio)

                for linea in listabloqueflowexterna:
                    if re.findall("bandwidth", linea) or re.findall("percent", linea):
                        separacion = linea.split(" ")
                        for lineados in separacion:
                            try:
                                clasesnumeros.append(int(lineados))
                            except ValueError:
                                pass

                for i in clasesnumeros:
                    if i > 100:
                        porcentaje = int((i * 100) / bloquetps[1])
                        clasesnumeros.remove(i)
                        clasesnumeros.append(porcentaje)

                    for c in clasesnumeros:
                        if c > 100:
                            filtro = int((c * 100) / bloquetps[1])
                            clasesnumeros.remove(c)
                            clasesnumeros.append(filtro)

                if len(clasesvalores) == len(clasesnumeros):
                    diccionario = dict(zip(clasesvalores, clasesnumeros))

                else:
                    clasesnumeros = []
                    diccionario = {}

            return [clasesvalores, clasesnumeros, diccionario]

        bloqueflow = filtrarbloqueflow()
        #print(bloqueflow)

        def alarmas():

            if d_i[0] == "BCOFRANCES":
                messagebox.showwarning("Warning", "The VPN is BCOFRANCES, please check the additional peers")
            if d_i[1] != "":
                messagebox.showwarning("Warning", "IP sub was detected, please check the configuration")
            if d_i[11] != "":
                messagebox.showwarning("Warning", "The service have IPV6, please check")
            if datosvpn[4] != "":
                messagebox.showwarning("Warning", "This VPN have an export map, please check and add it")
            if l_a_peer[9] == True:
                messagebox.showwarning("Warning", "The peer have a password, please ask the customer")
            if l_a_peer[14] == True:
                messagebox.showwarning("Warning", "The peer have RIP configuration, please check and add it")

        alarmas()

    ################################################################################################################

        scriptservicio = open(script, "a")

        def scriptgestion():

            entrada = "############# NAME SERVICE\n#\n#\n"
            switch = ""
            electrico = ""
            fibra = ""
            h_cinco = ""
            core = ""

            if nameservice != "":
                entrada = entrada.replace("NAME SERVICE", nameservice)

            if (opcion.get()==1):

                switch = "interface GigabitEthernetX/X/X.4002\n vlan-type dot1q 4002\
                    \n description Conexion con NAME SERVICE Tipo: Gestion S2300\n ip binding vpn-instance Mgmt-HL5\
                    \n ip address unnumbered interface Loopback4002\n statistic enable\n dhcp select relay\
                    \n ip relay address 10.105.10.109\n#\ninterface GigabitEthernetX/X/X.4000\
                    \n vlan-type dot1q 4000\n description Conexion con NAME SERVICE Tipo: Gestion S2300\
                    \n ip binding vpn-instance Mgmt-HL5\n ip address unnumbered interface Loopback4000\
                    \n statistic enable\n#\
                    \nip route-static vpn-instance Mgmt-HL5 LOOPBACK 255.255.255.255 GigabitEthernetX/X/X.4000 LOOPBACK\
                    \n#\ninterface GigabitEthernetX/X/X\
                    \ndescription Conexion con NAME SERVICE ID: IDNUMBER ADRED: ADREDNUMBER Tipo: Acceso\n#\n#####\n#\n"

                switch = switch.replace("X/X/X", ingresarinterfazh4).replace("NAME SERVICE", nameservice)
                switch = switch.replace("LOOPBACK", str(loopback)).replace("IDNUMBER", idnumber)
                switch = switch.replace("ADREDNUMBER", adrednumber)

            elif (opcion.get()==2):

                electrico = "interface GigabitEthernetX/X/X\n undo shutdown\
                            \n description Conexion con TM_T5 Tipo: Acceso (T-Marc)\n#\n######\n#\n"

                electrico = electrico.replace("X/X/X", ingresarinterfazh4).replace("T5", nameservice)

            elif (opcion.get()==3):

                fibra = "interface GigabitEthernetX/X/X\n undo shutdown\
                \n description Conexion con TM_T5 Tipo: Acceso (T-Marc)\n#\
                \ninterface GigabitEthernetX/X/X.999\n vlan-type dot1q 999\
                \n description GESTION:TMARC TM_T5 (T-Marc)\n ip binding vpn-instance TELCO_TMARC\
                \n ip address unnumbered interface LoopBack 999\n statistic enable\n#\
                \nip route-static vpn-instance TELCO_TMARC IPG 255.255.255.255 GigabitEthernetX/X/X.999 IPG description *** TM_T5 ***\n#\n######\n#\n"

                fibra = fibra.replace("X/X/X", ingresarinterfazh4).replace("T5", nameservice).replace("IPG", loopback)

            elif (opcion.get() == 4):

                h_cinco = "interface GigabitEthernetX/X/X\
                \n description Conexion con NAME SERVICE ID: IDNUMBER ADRED: ADREDNUMBER Tipo: Acceso\n#\
                \n interface GigabitEthernetX/X/X.4002\n vlan-type dot1q 4002\
                \n description Conexion con NAME SERVICE Tipo: Acceso\n ip binding vpn-instance Mgmt-HL5\
                \n ip address unnumbered interface Loopback4002\n statistic enable\n dhcp select relay\
                \n ip relay address 10.105.10.109\n dhcp snooping enable\n#\n#####\n#\n"

                h_cinco = h_cinco.replace("X/X/X", ingresarinterfazh4).replace("NAME SERVICE", nameservice).replace\
                        ("IDNUMBER", idnumber).replace("ADREDNUMBER", adrednumber)

            elif (opcion.get() == 5):

                core = "interface GigabitEthernetX/X/X\
                        \n description Conexion con NAME SERVICE\n#\n#####\n#\n"

                if d_i[5] != "":
                    core = core.replace("NAME SERVICE", d_i[5]).replace("X/X/X", ingresarinterfazh4)
                elif l_a_peer[4] != "":
                    core = core.replace("NAME SERVICE", l_a_peer[4]).replace("X/X/X", ingresarinterfazh4)

            return [entrada, switch, electrico, fibra, h_cinco, core]

        templatecero = scriptgestion()
        templateent = templatecero[0]
        templatesw = templatecero[1]
        templateelec = templatecero[2]
        templatefibra = templatecero[3]
        templatehcinco = templatecero[4]
        templatecore = templatecero[5]

        def scriptinterfaz():

            inter = "interface GigabitEthernetX/X/X.VLANC\n shutdown\n Vlan-type dot1q VLANUNO\
                \n encapsulation qinq-termination\n qinq termination pe-vid VLANUNO ce-vid VLANDOS\
                \n ip binding vpn-instance VPN\n description DESCRI\n ip address IPMASCARA\
                \n ip address SUBIM sub\n traffic-policy TPE inbound\n traffic-policy TPS outbound\
                \n qos-profile FLOW outbound\n statistic enable\n trust upstream default\
                \n arp broadcast enable\n commit\n#\n#"

            if d_i[10] == "":
                inter = inter.replace(" shutdown", "")

            if ingresarinterfazh4 != "":
                inter = inter.replace("X/X/X", ingresarinterfazh4)

            if d_i[6] != "" and d_i[7] != "" and opcion.get()==2:
                inter = inter.replace(" qinq termination pe-vid VLANUNO ce-vid VLANDOS", "")
                inter = inter.replace(" encapsulation qinq-termination", "").replace(" arp broadcast enable","")
                inter = inter.replace("VLANC", d_i[7]).replace("VLANUNO", d_i[7])

            if d_i[6] != "" and d_i[7] == "" and opcion.get() == 2:
                inter = inter.replace(".VLANC", "").replace(" encapsulation qinq-termination", "")
                inter = inter.replace(" qinq termination pe-vid VLANUNO ce-vid VLANDOS", "")
                inter = inter.replace(" arp broadcast enable", "").replace(" Vlan-type dot1q VLANUNO", "")

            if d_i[6] != "" and d_i[7] != "":
                inter = inter.replace(" Vlan-type dot1q VLANUNO", " ")
                inter = inter.replace("VLANC", d_i[6] + d_i[7])
                inter = inter.replace("VLANUNO", d_i[6]).replace("VLANDOS", d_i[7])

            if d_i[6] != "" and d_i[7] == "":
                inter = inter.replace(" encapsulation qinq-termination\n", "").replace(" arp broadcast enable\n","")
                inter = inter.replace(" qinq termination pe-vid VLANUNO ce-vid VLANDOS", "")
                inter = inter.replace("VLANC", d_i[6] + d_i[7]).replace("VLANUNO",
                                                                                                  d_i[6])
            if d_i[6] == "" and d_i[7] == "":
                inter = inter.replace(".VLANC", "").replace(" encapsulation qinq-termination\n", "")
                inter = inter.replace(" qinq termination pe-vid VLANUNO ce-vid VLANDOS", "")
                inter = inter.replace(" arp broadcast enable\n", "").replace(" Vlan-type dot1q VLANUNO", "")

            inter = inter.replace("VPN", d_i[0]) if d_i[0] != "" else inter.replace("VPN", "INFOINTERNET")
            inter = inter.replace("DESCRI", d_i[5]) if d_i[5] != "" else inter.replace(" description DESCRI", "")
            inter = inter.replace("IPMASCARA", d_i[3] + " " + d_i[4]) if d_i[3] != "" else inter.\
                    replace(" ip address IPMASCARA", "")
            inter = inter.replace("SUBIM", d_i[1] + " " + d_i[2]) if d_i[1] != "" else inter.\
                    replace(" ip address SUBIM sub", "")
            inter = inter.replace("TPE", d_i[8]) if d_i[8] != "" else inter.replace(" traffic-policy TPE inbound", "")

            if d_i[9] != "" and d_i[9] == d_i[8]:
                inter = inter.replace("TPS", d_i[9]).replace(" qos-profile FLOW outbound", "")
            if d_i[9] != "" and d_i[9] != d_i[8]:
                inter = inter.replace(" traffic-policy TPS outbound", "").replace("FLOW", d_i[9])
            else:
                inter = inter.replace(" traffic-policy TPS outbound", "")
                inter = inter.replace(" qos-profile FLOW outbound", "")

            inter = "".join([linea for linea in inter.strip().splitlines(True) if linea.strip()])
            inter = inter + "\n"

            return inter

        templateuno = scriptinterfaz()

        def scriptbgp():

            if d_i[0] != "":

                bgp = "bgp 22927\n ipv4-family vpn-instance VPN\n import-route direct\n import-route static\
                   \n maximum load-balancing ibgp ML\n peer X.X.X.X as-number ASN\n peer X.X.X.X description DESC\
                   \n peer X.X.X.X advertise-community\n peer X.X.X.X keep-all-routes\n peer X.X.X.X substitute-as\
                   \n peer X.X.X.X fake-as 10834\n peer X.X.X.X route-limit RL\n peer X.X.X.X default-route-advertise\
                   \n peer X.X.X.X password cipher xxx\n peer X.X.X.X ebgp-max-hop NUMAX\n peer X.X.X.X AWS\
                   \n peer X.X.X.X route-update-interval RUI\n peer X.X.X.X RREFLECTOR\n peer X.X.X.X enable\n#\n#"

                bgp = bgp.replace("VPN", d_i[0])

                if l_a_peer[0] == False:
                    bgp = bgp.replace(" import-route static", "")

                bgp = bgp.replace(" maximum load-balancing ibgp ML", "") if l_a_peer[1] == 0 else bgp.replace\
                    ("ML", l_a_peer[1])

                if l_a_peer[2] == False or datopeer == "":
                    bgp = bgp.replace(" peer X.X.X.X default-route-advertise", "")

                bgp = bgp.replace("ASN", l_a_peer[3]) if l_a_peer[3] != 0 else bgp.replace("ASN", "XXX")

                if l_a_peer[4] != "":
                    bgp = bgp.replace("DESC", l_a_peer[4])
                if l_a_peer[4] == "" and d_i[5] != "" and datopeer != "":
                    bgp = bgp.replace("DESC", d_i[5])
                else:
                    bgp = bgp.replace(" peer X.X.X.X description DESC", "")

                if l_a_peer[5] == False:
                    bgp = bgp.replace(" peer X.X.X.X keep-all-routes", "")

                bgp = bgp.replace(" peer X.X.X.X route-limit RL", "") if l_a_peer[6] == False else bgp.replace\
                    ("RL", l_a_peer[6])

                if l_a_peer[7] == False:
                        bgp = bgp.replace(" peer X.X.X.X advertise-community", "")

                if l_a_peer[8] == False:
                        bgp = bgp.replace(" peer X.X.X.X substitute-as", "")

                if l_a_peer[9] == False:
                    bgp = bgp.replace(" peer X.X.X.X password cipher xxx", "")

                bgp = bgp.replace(" peer X.X.X.X ebgp-max-hop NUMAX", "") if l_a_peer[10] == 0 else bgp.replace\
                    ("NUMAX", l_a_peer[10])

                bgp = bgp.replace(" peer X.X.X.X AWS", "") if l_a_peer[11] == "" else bgp.replace\
                    ("AWS", l_a_peer[11])

                bgp = bgp.replace(" peer X.X.X.X RREFLECTOR", "") if l_a_peer[12] == "" else bgp.replace\
                    ("RREFLECTOR", l_a_peer[12])

                bgp = bgp.replace(" peer X.X.X.X route-update-interval RUI", "") if l_a_peer[13] == 0 else bgp.replace\
                    ("RUI", l_a_peer[13])

                if datopeer != "":
                    bgp = bgp.replace("X.X.X.X", datopeer)
                else:
                    bgp = bgp.replace(" peer X.X.X.X enable", "").replace(" peer X.X.X.X fake-as 10834", "").replace\
                    (" peer X.X.X.X as-number XXX", "")

                bgp = "".join([linea for linea in bgp.strip().splitlines(True) if linea.strip()])
                bgp = bgp + "\n"

                return bgp

        templatedos = scriptbgp()

        def scriptvpn():

            if d_i[0] != "":

                inicio = "ip vpn-instance VPN\n description ### DESCR ###\n ipv4-family\n  route-distinguisher RD\n"
                rte = ["  vpn-target", " ", "VTE", " ", "export-extcommunity\n"] * len(datosvpn[1])
                rti = ["  vpn-target", " ", "VTI", " ", "import-extcommunity\n"] * len(datosvpn[2])
                final = "  apply-label per-instance\n#\n#\n"

                inicio = inicio.replace("DESCR", datosvpn[3]) if datosvpn[3] else inicio.replace("DESCR", d_i[0])
                inicio = inicio.replace("VPN", d_i[0]).replace("RD", datosvpn[0])

                contadore = len(datosvpn[1]) - 1
                contadori = len(datosvpn[2]) - 1
                incrementarte = 2
                incrementarutae = 0
                incrementarti = 2
                incrementarutai = 0

                while contadore >= 0:
                    rte[incrementarte] = datosvpn[1][incrementarutae]
                    incrementarte += 5
                    incrementarutae += 1
                    contadore -= 1

                while contadori >= 0:
                    rti[incrementarti] = datosvpn[2][incrementarutai]
                    incrementarti += 5
                    incrementarutai += 1
                    contadori -= 1

                rte = "".join(rte)
                rti = "".join(rti)

                vpn = inicio + rte + rti + final

                return vpn

        templatetres = scriptvpn()

        def scriptflow():

            if bloquetps[0] != "":

                diccionario = bloqueflow[2]
                clasesflow = bloqueflow[0]
                porcentajeflow = bloqueflow[1]

                inicio = "flow-queue FLOW\n  queue ef pq shaping shaping-percentage EF\n"
                mitad = ["  queue", " ", "afx", " ", "wfq", " ", "weight", " ", "AFX\n"] * len(bloqueflow[0])
                final = "  quit\ncommit\n#\nqos-profile TPS\n user-queue cir BANDW flow-queue FLOW\n#\n#\n"

                inicio = inicio.replace("FLOW", bloquetps[0])
                final = final.replace("FLOW", bloquetps[0]).replace("BANDW", str(bloquetps[1])).replace("TPS", d_i[9])

                contadorout = len(bloqueflow[0]) - 1
                iclase = 2
                flowc = 0

                while contadorout >= 0:
                    mitad[iclase] = clasesflow[flowc]
                    iclase += 9
                    flowc += 1
                    contadorout -= 1

                if diccionario != {}:

                    contador = len(bloqueflow[0]) - 1
                    iporcentaje = 8
                    flown = 0

                    for i in diccionario:
                        if i == "EF":
                            inicio = inicio.replace("EF", str(diccionario["EF"]))
                        else:
                            inicio = inicio.replace("  queue ef pq shaping shaping-percentage EF", "")

                    while contador >= 0:
                        mitad[iporcentaje] = str(porcentajeflow[flown]) + "\n"
                        iporcentaje += 9
                        flown += 1
                        contador -= 1

                else:
                    messagebox.showwarning("Warning", "Please add the flow queue values")

                for x in mitad:
                    if re.findall("EF", x):
                        EFindex = int(mitad.index("EF"))
                        del mitad[(EFindex - 1):(EFindex + 8)]

                mitad = "".join(mitad)
                flow = inicio + mitad + final
                flow = "".join([linea for linea in flow.strip().splitlines(True) if linea.strip()]) + "\n"

                return flow

        templatecuatro = scriptflow()

        def scripttpe():

            tpentrante = None

            if d_i[8] != "":

                tpentrante = "traffic classifier default\n if-match any\n commit\n quit\n#\ntraffic behavior ENLACE\
                        \n car cir DATOUNO cbs DATODOS pbs DATOTRES green pass red discard\n#\n traffic policy ENLACE\
                        \n undo share-mode\n statistics enable\n classifier default behavior ENLACE\n#\n#"

                tpentrante = tpentrante.replace("ENLACE", d_i[8])

                if len(bloquetpe) == 3:
                    tpentrante = tpentrante.replace("DATOUNO", str(bloquetpe[0])).replace\
                                ("DATODOS", str(bloquetpe[1])).replace("DATOTRES", str(bloquetpe[2]))
                if len(bloquetpe) == 2:
                    tpentrante = tpentrante.replace("DATOUNO", str(bloquetpe[0])).replace\
                                ("DATODOS", str(bloquetpe[1])).replace(" pbs DATOTRES green pass red discard", "")
                if len(bloquetpe) == 1:
                    tpentrante = tpentrante.replace("DATOUNO", str(bloquetpe[0])).replace\
                                (" cbs DATODOS pbs DATOTRES green pass red discard", "")

                tpentrante = tpentrante + "\n"

            return tpentrante

        templatecinco = scripttpe()

        def rutas():

            if datorutas != []:

                rutas = ("".join(datorutas) + "#\n#\n").strip()
                rutas = rutas + "\n"

                return rutas

        templateseis = rutas()

        def repeticion():

            repetidotpe = False
            repetidovpn = False
            for x in listascript:
                if re.findall(d_i[8], x):
                    repetidotpe = True
            for x in listascript:
                if re.findall("ip vpn-instance " + d_i[0], x):
                    repetidovpn = True

            return [repetidotpe, repetidovpn]

        repetir = repeticion()

        try:
            scriptservicio.write(templateent)
        except TypeError:
            pass
        if templatesw != "":
            try:
                scriptservicio.write(templatesw)
            except TypeError:
                pass
        if templateelec != "":
            try:
                scriptservicio.write(templateelec)
            except TypeError:
                pass
        if templatefibra != "":
            try:
                scriptservicio.write(templatefibra)
            except TypeError:
                pass
        if templatehcinco != "":
            try:
                scriptservicio.write(templatehcinco)
            except TypeError:
                pass
        if templatecore != "" and d_i[6] != "":
            try:
                scriptservicio.write(templatecore)
            except TypeError:
                pass
        if repetir[0] == False:
            try:
                scriptservicio.write(templatecinco)
            except TypeError:
                pass
        if repetir[1] == False:
            try:
                scriptservicio.write(templatetres)
            except TypeError:
                pass
        try:
            scriptservicio.write(templatedos)
        except TypeError:
            pass
        try:
            scriptservicio.write(templatecuatro)
        except TypeError:
            pass
        try:
            scriptservicio.write(templateuno)
        except TypeError:
            pass
        try:
            scriptservicio.write(templateseis)
        except TypeError:
            pass

        messagebox.showinfo("successful", "The configuration was created successfully")
        continuar = messagebox.askquestion("Cotinue", "Do you want continue with another service?")

        if continuar == "no":
            scriptservicio.close()
            raiz.destroy()
        else:
            cuadrouno.delete("0", END)
            cuadrodos.delete("0", END)
            cuadrotres.delete("0", END)
            cuadrocuatro.delete("0", END)
            cuadrocinco.delete("0", END)
            cuadroseis.delete("0", END)

    else:
        messagebox.showwarning("Warning", "Please enter the current port, select the core and .txt file you want to edit")

    ###############################################################################################################

raiz = Tk()
raiz.title("Script Generator")
raiz.resizable(False,False)
raiz.geometry("260x375")
raiz.config(relief="ridge", pady=20, background="#474343")
raiz.config(bd=5)

miframe=Frame()
miframe.pack()
miframe.config(width="70", height="50", pady=10, background="#474343")

mi_font = tkFont.Font(family="Arial", size=10, weight="bold", slant="italic")

def cuadros():

    tipovariable = StringVar
    cuadrouno = Entry(miframe, width=15)
    cuadrouno.grid(row=1, column=1, padx=5, pady=5)
    cuadrodos = Entry(miframe, width=15)
    cuadrodos.grid(row=2, column=1, padx=5, pady=5)
    cuadrotres = Entry(miframe, width=15)
    cuadrotres.grid(row=3, column=1, padx=5, pady=5)
    cuadrocuatro = Entry(miframe, width=15)
    cuadrocuatro.grid(row=4, column=1, padx=5, pady=5)
    cuadrocinco = Entry(miframe,width=15)
    cuadrocinco.grid(row=5, column=1, padx=5, pady=5)
    cuadroseis = Entry(miframe,width=15)
    cuadroseis.grid(row=6, column=1, padx=5, pady=5)
    cuadrosiete = Entry(miframe, width=15)
    cuadrosiete.grid(row=9, column=0, padx=5, pady=5)
    cuadroocho = Entry(miframe, width=15)
    cuadroocho.grid(row=9, column=1, padx=5, pady=5)

    return [cuadrouno, cuadrodos, cuadrotres, cuadrocuatro, cuadrocinco, cuadroseis, cuadrosiete, cuadroocho]

cuadrosall = cuadros()
cuadrouno = cuadrosall[0]
cuadrodos = cuadrosall[1]
cuadrotres = cuadrosall[2]
cuadrocuatro = cuadrosall[3]
cuadrocinco = cuadrosall[4]
cuadroseis = cuadrosall[5]
cuadrosiete = cuadrosall[6]
cuadroocho = cuadrosall[7]

def label():

    labelcero = Label(raiz, text="Enterprise Service", background="#474343", fg= "#B9B4C3")
    labelcero.place(x=65, y=-15)
    labelcero.config(font=mi_font)
    labeluno = Label(miframe, text="Old Interface:", background="#474343", fg= "#B9B4C3")
    labeluno.grid(row=1, column=0)
    labeluno.config(font=("Courier", 9, "italic"))
    labeldos = Label(miframe, text="New Interface:", background="#474343", fg= "#B9B4C3")
    labeldos.grid(row=2, column=0)
    labeldos.config(font=("Courier", 9, "italic"))
    labeltres = Label(miframe, text="ID Red (Path):", background="#474343", fg= "#B9B4C3")
    labeltres.grid(row=3, column=0)
    labeltres.config(font=("Courier", 9, "italic"))
    labelcuatro = Label(miframe, text="Adred-Adecir:", background="#474343", fg= "#B9B4C3")
    labelcuatro.grid(row=4, column=0)
    labelcuatro.config(font=("Courier", 9, "italic"))
    labelcinco = Label(miframe, text="LoopBack193:", background="#474343", fg= "#B9B4C3")
    labelcinco.grid(row=5, column=0)
    labelcinco.config(font=("Courier", 9, "italic"))
    labelseis = Label(miframe, text="Service Name:", background="#474343", fg= "#B9B4C3")
    labelseis.grid(row=6, column=0)
    labelseis.config(font=("Courier", 9, "italic"))
    labelsiete = Label(miframe, text="------------------------------------------", background="#474343", fg= "#B9B4C3")
    labelsiete.grid(row=8, column=0, columnspan=2)

label()

def abrirfichero():

    buscarcore = filedialog.askopenfilename(initialdir="/", title="Selecciona el archivo",
                                            filetypes=(("txt files","*.txt"), ("all files", "*.*")))
    cuadrosiete.insert(0, buscarcore)

def crearfichero():

    buscarcfg = filedialog.askopenfilename(initialdir="/", title="Selecciona el archivo",
                                            filetypes=(("txt files","*.txt"), ("all files", "*.*")))
    cuadroocho.insert(0, buscarcfg)

def borrartexto():

    cuadrouno.delete("0", END)
    cuadrodos.delete("0", END)
    cuadrotres.delete("0", END)
    cuadrocuatro.delete("0", END)
    cuadrocinco.delete("0", END)
    cuadroseis.delete("0", END)
    cuadrosiete.delete("0", END)
    cuadroocho.delete("0", END)

def botones():

    botonuno = Button(miframe, text="Look Core", width=12, command=abrirfichero)
    botonuno.grid(row=10, column=0)
    botonuno.config(font=("Courier", 9, "italic"))
    botondos = Button(miframe, text="Create .txt", width=12, command=crearfichero)
    botondos.grid(row=10, column=1)
    botondos.config(font=("Courier", 9, "italic"))
    botontres = Button(miframe, text="Start", width=12, background="#859E84", command=ejecucion)
    botontres.grid(row=12, column=0)
    botontres.config(font=("Courier", 9, "italic"))
    botoncuatro= Button(miframe, text="Remove all", width=12, background="#FFA6AD", command=borrartexto)
    botoncuatro.grid(row=12, column=1, pady=5)
    botoncuatro.config(font=("Courier", 9, "italic"))

botones()

menuboton = Menubutton(raiz, text="Service Type", background="#474343", fg="#B9B4C3")
menuboton.config(font=mi_font)
menuboton.menu = Menu(menuboton, tearoff=0)
menuboton["menu"] = menuboton.menu

opcion = IntVar()
radiouno = menuboton.menu.add_radiobutton(label="S2300", variable=opcion, value=1)
radiodos = menuboton.menu.add_radiobutton(label="T5-UTP", variable=opcion, value=2)
radiotres = menuboton.menu.add_radiobutton(label="T5-Fibra", variable=opcion, value=3)
radiocuatro = menuboton.menu.add_radiobutton(label="H5", variable=opcion, value=4)
radiocinco = menuboton.menu.add_radiobutton(label="Core", variable=opcion, value=5)
radioseis = menuboton.menu.add_radiobutton(label="N/A", variable=opcion, value=6)
menuboton.pack(side=tkinter.BOTTOM, pady=0)

raiz.mainloop()



