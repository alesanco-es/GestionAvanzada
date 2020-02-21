#!/usr/bin/python
# -*- coding: utf-8 -*-

# Información sobre XML en python en https://docs.python.org/2/library/xml.dom.html#module-xml.dom


from lxml import etree as ET
from pysnmp.proto import error, rfc1902
import pysnmp.smi.error
from pysnmp.entity import engine, config
import ast

def verifyAccess(self, name, idx, viewType,
                       snmpEngine, securityModel, securityName,
                        securityLevel, contextName
                       ):
    try:
        vacmID = 3
        # clave para interpretar las variables que se introducen http://www.rfc-base.org/txt/rfc-2575.txt
        statusInformation = snmpEngine.accessControlModel[vacmID].isAccessAllowed(
            snmpEngine, securityModel, securityName,
            securityLevel, viewType, contextName, name
            )
    except error.StatusInformation, statusInformation:
        errorIndication = statusInformation['errorIndication']
        if str(errorIndication) == 'Requested OID is out of MIB view':
           raise pysnmp.smi.error.AuthorizationError(
                    name=name, idx=idx
                    )

def createMibTree(self):
    doc="""<?xml version="1.0" encoding="utf-8"?>
    <OidTree>
        <o1 NAME= "" SYNTAX="none" MAX-ACCESS="not-accessible">
            <o1o3 NAME= "" SYNTAX="none" MAX-ACCESS="not-accessible">
                <o1o3o6 NAME= "" SYNTAX="none" MAX-ACCESS="not-accessible">
                    <o1o3o6o1 NAME= "" SYNTAX="none" MAX-ACCESS="not-accessible">
                        <o1o3o6o1o4 NAME= "" SYNTAX="none" MAX-ACCESS="not-accessible">
                            <o1o3o6o1o4o1 NAME= "" SYNTAX="none" MAX-ACCESS="not-accessible">
                                <o1o3o6o1o4o1o28308 NAME= "" SYNTAX="none" MAX-ACCESS="not-accessible">
                                        #...#
                                </o1o3o6o1o4o1o28308>
                            </o1o3o6o1o4o1>
                        </o1o3o6o1o4>
                    </o1o3o6o1>
                </o1o3o6>
            </o1o3>
        </o1>
    </OidTree>
    """
    self.mib_xml = ET.fromstring(doc)



def get_snmp(self,oid_o):
    # Necesito que devuelva un OID, un valor, un tipo de datos y los errores
    oid = 'o' + oid_o.replace('.','o')
    find_oid_get = ET.XPath("//"+oid+'[@SYNTAX!="none" and @MAX-ACCESS!="not-accessible"]')

    node_O = find_oid_get(self.mib)

    print node_O
    try:
        node_X = node_O[0]
    except:
        oid_s = oid_o
        value = 'noSuchName'
        type_v = 'noSuchName'
        return [oid_s, value, type_v]
    else:
        oid_s = node_X.tag.replace('o','.')[1:]
        if node_X.text is None:
            value = ''
        else:
            value = node_X.text
        type_v = node_X.get('SYNTAX')
        return [oid_s, value, type_v]


# https://stackoverflow.com/questions/6289646/python-function-as-a-function-argument
# https://stackoverflow.com/questions/3061/calling-a-function-of-a-module-from-a-string-with-the-functions-name-in-python
def usmVacmSetup(self,file_name):
    tree = ET.parse(file_name)
    root = tree.getroot()
    self.iniFile = root
    # findall encuentra todos los hijos directos
    ### Usuarios
    users = root.find('users')
    users = users.findall('user')
    for user in users:
        # find encuentra el primer hijo con ese nombre
        name = user.get('securityName')
        level = user.find('level').text
        if level == 'authNoPriv':
            authAlg = user.find('authAlg').text
            authKey = user.find('authAlg').get('key')
            config.addV3User(self.snmpEngine, name,getattr(config, authAlg), authKey,)
        elif level == 'authPriv':
            #...
            config.addVacmUser(self.snmpEngine, 3, name, level)
    ### Grupos
    #...
    config.addVacmGroup(self.snmpEngine, groupName, 3, securityName)
    #...
    ### Vistas
    #...
    config.addVacmView(self.snmpEngine, viewName, "included", ast.literal_eval(oid), "")
    #...
    ### Access
    #...
    config.addVacmAccess(self.snmpEngine, groupName, "", 3, level, "exact", read, write, notify)
    #...
