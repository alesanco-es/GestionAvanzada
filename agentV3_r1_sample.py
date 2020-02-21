#!/usr/bin/python
# -*- coding: utf-8 -*-

from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import cmdrsp, context, ntforg
from pysnmp.carrier.asynsock.dgram import udp
from pysnmp.proto.api import v2c
from pysnmp.smi import exval
from agent_v3_tools import verifyAccess, \
    createMibTree, get_next_snmp, get_snmp, set_snmp, usmVacmSetup
from lxml import etree as ET
from datetime import datetime
import signal
import time
import os


class agent_v3:
    ########################################################################################
    ### Variables que van a ser atributos de la clase, para
    ### ser accesibles desde cualquier método
    ########################################################################################
    # Contiene la instancia de la MIB
    mib_xml = []
    # Contiene el Notification Originator (en caso de implementarlo)
    ntfOrg = []
    # Contiene el SNMP Engine (elemento central del Agente)
    snmpEngine = []
    # Contiene el contenido del fichero de configuración
    iniFile = []

    def update_table(self,signum, stack):
        # Actualizo la tabla
        for i in range(2,0,-1):
            # Selecciono la fila origen y saco sus valores
            oid = 'o1o3o6o1o4o1o28308o1o3o1o2o' + str(i)
            node_O = self.mib_xml.xpath()
            #...
            # para desplazarlos a la fila destino
            #...
        # Actualizo el valor puntual
        oid = 'o1o3o6o1o4o1o28308o1o3o1o2o1'
        node_O = self.mib_xml.xpath()
        node_O[0].text = str(int(os.getloadavg()[1]*100))
        #...
        # https://tools.ietf.org/html/draft-ietf-snmpv2-tc-02
        #1992-5-26,13:30:15.0,-4:0
        fecha = datetime.today()
        #...
        signal.alarm(60)


    def __init__(self, filename):
    # Configuramos la alarma y la llamo para ir rellenando la MIB
	signal.signal(signal.SIGALRM, self.update_table)
	signal.alarm(5)
        # Creo la MIB, mediate el uso de una función propia
        createMibTree(self)
        # Creo el SNMP engine
        snmpEngine = engine.SnmpEngine()
        self.snmpEngine = snmpEngine
        # Obtengo el SNMP context por defecto del SNMP engine
        snmpContext = context.SnmpContext(snmpEngine)
        # SNMPv3 VACM / USM setup
        usmVacmSetup(self,filename)
        # Transport setup: UDP over IPv4
        # he tenido que meter udp.domainName + (1,) porque sino me decia cuando abria
        # el socket para mandar traps que ya esta siendo utilizado ese dominio
        # http://sourceforge.net/p/pysnmp/mailman/message/26146019/
        ip_addr = self.iniFile.xpath()
        port = self.iniFile.xpath()
        config.addSocketTransport(
            snmpEngine,
            udp.domainName + (1,),
            udp.UdpTransport().openServerMode((ip_addr, int(port)))
        )
        # Register SNMP Applications at the SNMP engine for particular SNMP context
        #cmdrsp.GetCommandResponder(snmpEngine,snmpContext)
        GCR = GetCommandResponder(snmpEngine, snmpContext, self.mib_xml)
        SCR = SetCommandResponder(snmpEngine, snmpContext, self.mib_xml)
        NCR = NextCommandResponder(snmpEngine, snmpContext, self.mib_xml)
        # Run I/O dispatcher which would receive queries and send responses
	snmpEngine.transportDispatcher.jobStarted(1) # añadido 07/03/2017
        try:
            snmpEngine.transportDispatcher.runDispatcher()
        except:
            snmpEngine.transportDispatcher.closeDispatcher()
            raise


class GetCommandResponder (cmdrsp.GetCommandResponder):
    # La instancia de la MIB es atributo global para tener acceso desde todos los métodos
    mib=[]
    def __init__(self, snmpEngine, snmpContext, mib):
        cmdrsp.CommandResponderBase.__init__(self,snmpEngine,snmpContext)
        self.mib=mib

    def handleMgmtOperation(self, snmpEngine, stateReference, contextName,
                            PDU, acInfo):
        print('Estoy dentro de un GET')
        varBinds = v2c.apiPDU.getVarBinds(PDU)
        # Hay que verificar que el usuario tiene permiso para acceder al OID que solicita
        # acInfo es un tuple; acInfo[1][2] es el securityName: acInfo[1][3] es securityLevel
        # 2 --> authNoPriv 3 --> authPriv
        verifyAccess(self,varBinds[0][0],0,'read',snmpEngine,3,
                     acInfo[1][2],acInfo[1][3],contextName)
        # Procesado de la petición
        varBindsRsp=[]
        oid_o = str(varBinds[0][0])
        # result = [oid, value, type] de respuesta
        result = get_snmp(self,oid_o)
        if result[2] == 'noSuchObject':
            errorStatus = 0
            errorIndex = 0
            varBindsRsp.append((v2c.ObjectIdentifier(oid_o),
                                 exval.noSuchObject))
        else:
            if result[2] == 'integer':
                # Si la variable result[1] esta vacía (''), la conversión a objeto Int peta ...
                try:
                    varBindsRsp.append((v2c.ObjectIdentifier(result[0]),
                                     v2c.Integer(result[1])))
                except:
                    varBindsRsp.append((v2c.ObjectIdentifier(result[0]),
                                     v2c.null))
                # http://www.tek-tips.com/viewthread.cfm?qid=1698331
            elif result[2] == 'octet-string':
                varBindsRsp.append((v2c.ObjectIdentifier(result[0]),
                                 v2c.OctetString(result[1])))
            errorStatus = 0
            errorIndex = 0
        # Envío de la respuesta
        self.sendRsp(
            snmpEngine, stateReference,  errorStatus,
            errorIndex, varBindsRsp
        )

local_agent_v3 = agent_v3("snmp_config_file.xml")

