# Sample module in the public domain. Feel free to use this as a template
# for your modules (and you can remove this header and take complete credit
# and liability)
#
# Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
#
# This is free and unencumbered software released into the public domain.
#
# Anyone is free to copy, modify, publish, use, compile, sell, or
# distribute this software, either in source code form or as a compiled
# binary, for any purpose, commercial or non-commercial, and by any
# means.
#
# In jurisdictions that recognize copyright laws, the author or authors
# of this software dedicate any and all copyright interest in the
# software to the public domain. We make this dedication for the benefit
# of the public at large and to the detriment of our heirs and
# successors. We intend this dedication to be an overt act of
# relinquishment in perpetuity of all present and future rights to this
# software under copyright law.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.

# Simple data source-level ingest module for Autopsy.
# Used as part of Python tutorials from Basis Technology - August 2015
# 
# Looks for files of a given name, opens then in SQLite, queries the DB,
# and makes artifacts
from QNX6_FS import QNX6_FS
from struct import *
from datetime import datetime
import jarray
import inspect
import os
import time
from java.util import UUID
from java.lang import Class
from java.lang import System
from java.sql  import DriverManager, SQLException
from java.util.logging import Level
from java.util import ArrayList
from java.io import File
from org.sleuthkit.datamodel import SleuthkitCase
from org.sleuthkit.datamodel import AbstractFile
from org.sleuthkit.datamodel import ReadContentInputStream
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.ingest import ModuleDataEvent
from org.sleuthkit.autopsy.ingest import ModuleContentEvent
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.datamodel import ContentUtils
from org.sleuthkit.autopsy.casemodule.services import Services
from org.sleuthkit.autopsy.casemodule.services import FileManager
from org.sleuthkit.autopsy.casemodule.services import Blackboard


# Factory that defines the name and details of the module and allows Autopsy
# to create instances of the modules that will do the analysis.
class QNX6ReaderIngestModuleFactory(IngestModuleFactoryAdapter):

    moduleName = "QNX6 Parser"

    def getModuleDisplayName(self):
        return self.moduleName

    def getModuleDescription(self):
        return "Sample module that parses QNX6"

    def getModuleVersionNumber(self):
        return "1.0"

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return QNX6ReaderIngestModule()

# Data Source-level ingest module.  One gets created per data source.
class QNX6ReaderIngestModule(DataSourceIngestModule):

    _logger = Logger.getLogger(QNX6ReaderIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def __init__(self):
        self.context = None

    # Where any setup and configuration is done
    # 'context' is an instance of org.sleuthkit.autopsy.ingest.IngestJobContext.
    # See: http://sleuthkit.org/autopsy/docs/api-docs/latest/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_ingest_job_context.html
    def startUp(self, context):
        self.context = context

    
    # Where the analysis is done.
    # The 'dataSource' object being passed in is of type org.sleuthkit.datamodel.Content.
    # See: http://www.sleuthkit.org/sleuthkit/docs/jni-docs/latest/interfaceorg_1_1sleuthkit_1_1datamodel_1_1_content.html
    # 'progressBar' is of type org.sleuthkit.autopsy.ingest.DataSourceIngestModuleProgress
    # See: http://sleuthkit.org/autopsy/docs/api-docs/latest/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_data_source_ingest_module_progress.html
    def process(self, dataSource, progressBar):

        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()
        case =  Case.getCurrentCase()
        sKCase = case.getSleuthkitCase()
        wDirPath = case.getModuleDirectory()

        #Recuper le diskimg au format AbstractFile
        fileManager = case.getServices().getFileManager()
        qnx6Img = fileManager.findFiles(dataSource, "%%")[0]

        #sKCase.addAttrType("Striddddngdd "," String dispfflayName")
        
        #artIdAD1 = Case.getCurrentCase().getSleuthkitCase().addArtifactType( "AD1_EXTRACTOR", "AD1 Extraction")
        #artAD1 = qnx6Img.newArtifact(artIdAD1)
        #attributes = ArrayList()
        #attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_NAME, QNX6ReaderIngestModuleFactory.moduleName, "dddddzezz"))
        #attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_TEMP_DIR, QNX6ReaderIngestModuleFactory.moduleName, "ddd//dd"))    
        #artAD1.addAttributes(attributes)


        #blackboard.postArtifact(artAD1)

        qnx6fs = QNX6_FS(qnx6Img)
        #On recupere les information du premier super block
        SP = qnx6fs.getFirstSuperBlock()

        #Si il s agit bien d un FS QNX6
        if(qnx6fs.isQNX6FS(SP)):
            self.postMessage("QNX6 file system detected")

            #Creation d un rapport contenant les informations du super blocks
            self.createAndPostSBReport("QNX6SuperBlockReport.txt",wDirPath+"\\..\\Reports",SP)
            self.postMessage("File System report created")
          
            #Identification du SuperBlock actif
            sndSPBlockOffset = qnx6fs.getSndSPBlockOffset()
            sndSPBlock = qnx6fs.readSPBlock(sndSPBlockOffset)
            if(qnx6fs.isQNX6FS(sndSPBlock)):
                if(sndSPBlock['serial'] > SP['serial']):
                    SP = sndSPBlock


            #self.parseBitmap(SB)
            #self.LongNames = self.parseLongFileNames(SB)

            #Recuperation des inodes a partir des rootNodes
            inodeTree = qnx6fs.readBlockPointers(SP["RootNode"]['ptr'],SP["tailleBlock"],SP["SP_end"],SP['RootNode']['level'])

            #Recupere dans dirTree la liste des fichiers et repertoires
            dirTree,inodeTree = qnx6fs.parseINodeDIRStruct(inodeTree,SP['tailleBlock'],SP['SP_end'])
            self.log(Level.INFO, str(dirTree ))

            #Repertoire dans lequel extraire les donnees
            realRootDir = wDirPath+"\\"+dataSource.getName()+"\\Partition0"
            if(os.path.exists(realRootDir) == False):
                try: 
                    os.makedirs(realRootDir)
                except OSError as e:
                    pass 


            directoryTree = []
            for i in dirTree:
                if(i != 0l): #->Fichier supprime
                    rep = qnx6fs.genDirs(realRootDir,inodeTree,dirTree,i)
                    if(rep != None):
                        path = os.path.join(realRootDir+"\\"+rep["path"],rep["name"])
                        if(not os.path.exists(path)):
                            try: 
                                os.makedirs(path)
                            except OSError as e:
                                pass 
                        directoryTree.append(rep)
                        
            self.log(Level.INFO, str(directoryTree ))

            #for i in dirTree:
            #    if(i != 0l): #->Fichier supprime
            #        qnx6fs.dumpfile(realRootDir,inodeTree,dirTree,i, SP['tailleBlock'],SP['SP_end'],0)
            self.postMessage("Files extracted in "+ realRootDir)

            #Creation de l arboresence dans Autopsy
            virtualRootDir = Case.getCurrentCase().getSleuthkitCase().addLocalDirectory(dataSource.getId(),"Partition"+str(0))
            self.addTree(realRootDir,virtualRootDir)
        else:
            self.postMessage("No QNX6 file system detected")

        #On notifie Autopsy que des element ont ete ajoute a la data source
        Case.getCurrentCase().notifyDataSourceAdded(dataSource,  UUID.randomUUID())
        #IngestServices.getInstance().fireModuleContentEvent(ModuleContentEvent(dataSource))

        return IngestModule.ProcessResult.OK

    #Ajoute le contenu d un repertoire dans les datasource d autopsy
    def addTree(self,path,parent):
        sCase =  Case.getCurrentCase().getSleuthkitCase()
        for f in os.listdir(path):
            fpath = os.path.join(path, f)
            if os.path.isfile(fpath):
                sCase.addLocalFile(f,fpath,os.path.getsize(fpath), long(os.path.getctime(fpath)),long(os.path.getctime(fpath)),long(os.path.getatime(fpath)),long(os.path.getmtime(fpath)),True, parent )
            if os.path.isdir(fpath):
                rep = sCase.addLocalFile(f,fpath,os.path.getsize(fpath), long(os.path.getctime(fpath)),long(os.path.getctime(fpath)),long(os.path.getatime(fpath)),long(os.path.getmtime(fpath)),False, parent )
                self.addTree(fpath,rep)

    #Cherche le repertoire dans le data source ayant dirName comme nom
    def findAutopsyDir(self,dirName):
        for autopsyDir in self.autopsyLocalDirList:
            if(dirName == autopsyDir.getName()):
                return autopsyDir
        return self.autopsyLocalDirList[0]

    #Verifie que le repertoire ayant le nom dirName autopsy existe
    def dirNameIsAutopsyDir(self,dirName):
        for autopsyDir in self.autopsyLocalDirList:
            if(dirName == autopsyDir.getName()):
                return True
        return False

    #Permet de poster un message dans autopsy
    def postMessage(self,message):
        IngestServices.getInstance().postMessage(IngestMessage.createMessage(IngestMessage.MessageType.DATA,QNX6ReaderIngestModuleFactory.moduleName, message))

    #Creer un rapport contenant les informations du super block
    def createAndPostSBReport(self,filename,path,SP):
        if(not path):
            os.makedirs(path)
        filePath = os.path.join(path, filename)
        report = open(filePath, 'wb+')
        report.write("--QNX6FS Super Block infos--\n\n")
        report.write("Serial number : "+ hex(int(SP["serialNum"]))+"\n")
        report.write("Magic number : "+ hex(int(SP["magic"]))+"\n")
        report.write("File system creation time :  "+ datetime.fromtimestamp(int(SP['ctime'])).strftime("%m/%d/%Y, %H:%M:%S") + "\n")
        report.write("File system modification time :  "+ datetime.fromtimestamp(int(SP['ctime'])).strftime("%m/%d/%Y, %H:%M:%S")+ "\n")
        report.write("File system access time :  "+ datetime.fromtimestamp(int(SP['ctime'])).strftime("%m/%d/%Y, %H:%M:%S")+ "\n")
        #report.write("Volume ID : "+ SP["volumeid"]+"\n")
        report.write("Block Size : "+ str(int(SP["tailleBlock"]))+" bytes \n")
        report.write("Number of blocks : "+ hex(int(SP["numBlocks"]))+"\n")
        report.write("Number of free blocks : "+ hex(int(SP["blocksLibres"]))+"\n")
        report.write("Number of inodes : "+ hex(int(SP["numRootInodes"]))+"\n")
        report.write("Number of free inodes : "+ hex(int(SP["rootInodesLibres"]))+"\n")
        report.close()

        # Add the report to the Case, so it is shown in the tree
        Case.getCurrentCase().addReport(filePath, QNX6ReaderIngestModuleFactory.moduleName , "QNX6 Super Block Report")
