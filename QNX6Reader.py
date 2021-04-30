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
        progressBar.switchToDeterminate(100)
        progressBar.progress("Parsing Super Block",10)
        case =  Case.getCurrentCase()
        sKCase = case.getSleuthkitCase()
        wDirPath = case.getModuleDirectory()

        #Repertoire dans lequel extraire les donnees
        realRootDir = wDirPath+"\\"+dataSource.getName()+"\\Partition0"
        if(os.path.exists(realRootDir) == False):
            try: 
                os.makedirs(realRootDir)
            except OSError as e:
                pass 

        #Recuper le diskimg au format AbstractFile
        fileManager = case.getServices().getFileManager()
        qnx6Img = fileManager.findFiles(dataSource, "%%")[0]

        #Construciton de l'objet QNX6 permettant de recuperer les infos du superblock ect ...
        qnx6fs = QNX6_FS(qnx6Img)

        #Il faudrait prendre en compte la place occupe par la partition si il y en a
        FSoffset = 0 + qnx6fs.QNX6_BOOTBLOCK_SIZE
        #On recupere les information du premier super block
        SP = qnx6fs.readSPBlock(FSoffset)
        #La fin du super block 1 permet de calculer les addresses a partir des pointeurs
        SBend = SP["SP_end"]
        #Si il s agit bien d un FS QNX6
        if(qnx6fs.isQNX6FS(SP)):
            self.postMessage("QNX6 file system detected")

            #Creation d un rapport contenant les informations du super blocks
            self.createAndPostSBReport(dataSource.getName(),wDirPath+"\\..\\Reports",SP)
            self.postMessage("File System report created")
          
            #Identification du SuperBlock actif (Le super block ayant l ID le plus grand est le super block actif)
            #L autre block est le backupSuperBlock qui peut etre utile pour retrouver les donnees effavees
            sndSPBlockOffset = qnx6fs.getSndSPBlockOffset(SP)
            sndSPBlock = qnx6fs.readSPBlock(sndSPBlockOffset)
            backUpSB = sndSPBlock
            if(qnx6fs.isQNX6FS(sndSPBlock)):
                if(sndSPBlock['serialNum'] > SP['serialNum']):
                    backUpSB = SP
                    SP = sndSPBlock


            #Recuperation des inodes a partir des rootNodes du superBlock actif
            progressBar.progress("Parsing inodes",20)
            inodeTree = qnx6fs.readBlockPointers(SP["RootNode"]['ptr'],SP["tailleBlock"],SBend,SP['RootNode']['level'])

            #Recuperation des inodes a partir des rootNodes du backup superBlock (utile pour retrouver les donnees effacees)
            backUpInodeTree = qnx6fs.readBlockPointers(backUpSB["RootNode"]['ptr'],backUpSB["tailleBlock"],SBend,backUpSB['RootNode']['level'])

            #On recupere les inodes correspondant a des fichier dont le nom est long (traite differement)
            longNameObj = qnx6fs.parseLongFileNames(SP)

            
            #Recupere dans dirTree un dictionaire contenant l id des dossiers et des fichiers ainsi que leurs noms et l id de leurs parents
            progressBar.progress("Parsing directory structure",65)
            dirTree = qnx6fs.parseINodeDIRStruct(inodeTree,backUpInodeTree,longNameObj,SP['tailleBlock'],SBend)

            #Affichage des inode dans le fichier de log
            self.log(Level.INFO, str(inodeTree ))
            self.log(Level.INFO, str(dirTree ))

           
            #On recupere la liste des fichiers et repertoires avec toutes les informations associees
            progressBar.progress("Files and dirs recovery from inodes",80)
            dirList,fileList = qnx6fs.getDirsAndFiles(inodeTree,dirTree,SP['tailleBlock'],SBend)

            #On cree un dossier special ou l on met les fichiers supprimees dont on a pas pu retrouver le path et le nom
            retrivedContentDirName = "retrieved_content//"
            dirPath = realRootDir+"\\"+ retrivedContentDirName
            if(not os.path.exists(dirPath)):
                try:
                    os.makedirs(dirPath)
                except OSError as e:
                    self.postMessage("Erreur lors de la creation de : "+ dirPath )

            #On recupere les fichiers supprimees dont on a pas pu retrouver le path et le nom
            deletedContent = qnx6fs.getDeletedContent(retrivedContentDirName,inodeTree,dirTree,SP['tailleBlock'],SBend)
            
            #On cree les dossiers retrouves dans un repertoire du projet
            progressBar.progress("Creation of recovered files and dirs",90)
            for rep in dirList:
                dirPath = realRootDir+"\\"+os.path.join(rep["path"],rep["name"])
                if(not os.path.exists(dirPath)):
                    try:
                        os.makedirs(dirPath)
                    except OSError as e:
                        self.postMessage("Erreur lors de la creation de : "+ dirPath )
                        self.log(Level.INFO, os.strerror(e.errno))
                        pass
            #On cree les fichiers retrouves dans un repertoire du projet
            for file in fileList+deletedContent:
                filePath = realRootDir+"\\"+os.path.join(file["path"],file["name"])
                if(not os.path.exists(filePath)):
                    try:
                        f = open(filePath,"wb+")
                        if(file["data"] != None):
                            f.write(file["data"])
                        f.close()
                    except IOError as e:
                        self.postMessage("Erreur lors de la creation de : "+ filePath )
                        self.log(Level.INFO, os.strerror(e.errno))
                        pass

            progressBar.progress("Creation of reports",95)
            self.postMessage("Files extracted in "+ realRootDir)

            #Creation de l arboresence dans Autopsy a partir de la datasource et des donnees retrouvees
            virtualRootDir = Case.getCurrentCase().getSleuthkitCase().addLocalDirectory(dataSource.getId(),"Partition"+str(0))
            self.addTree(realRootDir,virtualRootDir)

            #Creation du rapport contenant toutes les informations extraites
            self.createAndPostContentReport(dataSource.getName(), wDirPath+"\\..\\Reports",dirList, fileList+deletedContent)
        else:
            self.postMessage("No QNX6 file system detected")

        #On notifie Autopsy que des elements ont ete ajoute a la data source
        Case.getCurrentCase().notifyDataSourceAdded(dataSource,  UUID.randomUUID())
        progressBar.progress("Task completed",100)
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

    def createAndPostContentReport(self,name,path,dirList,fileList):
        filename = name + "ContentReport.txt"
        if(not path):
            os.makedirs(path)
        filePath = os.path.join(path, filename)
        report = open(filePath, 'wb+')
        report.write("------"+name+" QNX6FS Content Report------\n")

        report.write("\n\n------Directories Extracted------\n")
        for rep in dirList:
            report.write("Path : "+rep['path']+ "  |  Name : "+rep['name']+"  |  Size : "+str(rep['size'])+"  |  UID : "+str(rep['uid'])+"  |  GID : "+str(rep['gid'])+"  |  ftime : "+str(rep['ftime'])+"  |  atime : "+str(rep['atime'])+"  |  ctime : "+str(rep['ctime'])+"  |  mtime : "+str(rep['mtime'])+"  |  status : "+str(rep['status'])+"\n")

        report.write("\n\n------Files Extracted------\n")
        for file in fileList:
            report.write("Path : "+file['path']+ "  |  Name : "+file['name']+"  |  Size : "+str(file['size'])+"  |  UID : "+str(file['uid'])+"  |  GID : "+str(file['gid'])+"  |  ftime : "+str(file['ftime'])+"  |  atime : "+str(file['atime'])+"  |  ctime : "+str(file['ctime'])+"  |  mtime : "+str(file['mtime'])+"  |  status : "+str(file['status'])+"\n")
        report.close()
        # Add the report to the Case, so it is shown in the tree
        Case.getCurrentCase().addReport(filePath, QNX6ReaderIngestModuleFactory.moduleName , name + " Content report")

    #Creer un rapport contenant les informations du super block
    def createAndPostSBReport(self,name,path,SP):
        filename = name + "SuperBlockReport.txt"
        if(not path):
            os.makedirs(path)
        filePath = os.path.join(path, filename)
        report = open(filePath, 'wb+')
        report.write("------"+name+" QNX6FS Super Block informations------\n\n")
        report.write("Serial number : "+ hex(int(SP["serialNum"]))+"\n")
        report.write("Magic number : "+ hex(int(SP["magic"]))+"\n")
        report.write("File system creation time :  "+ datetime.fromtimestamp(int(SP['ctime'])).strftime("%m/%d/%Y, %H:%M:%S") + "\n")
        report.write("File system modification time :  "+ datetime.fromtimestamp(int(SP['ctime'])).strftime("%m/%d/%Y, %H:%M:%S")+ "\n")
        report.write("File system access time :  "+ datetime.fromtimestamp(int(SP['ctime'])).strftime("%m/%d/%Y, %H:%M:%S")+ "\n")
        report.write("Block Size : "+ str(int(SP["tailleBlock"]))+" bytes \n")
        report.write("Number of blocks : "+ hex(int(SP["numBlocks"]))+"\n")
        report.write("Number of free blocks : "+ hex(int(SP["blocksLibres"]))+"\n")
        report.write("Number of inodes : "+ hex(int(SP["numRootInodes"]))+"\n")
        report.write("Number of free inodes : "+ hex(int(SP["rootInodesLibres"]))+"\n")
        report.close()

        # Add the report to the Case, so it is shown in the tree
        Case.getCurrentCase().addReport(filePath, QNX6ReaderIngestModuleFactory.moduleName , name + " Super Block Report")
