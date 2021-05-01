from struct import *
from datetime import datetime
import jarray
import inspect
import os
from copy import deepcopy
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
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.datamodel import ContentUtils
from org.sleuthkit.autopsy.casemodule.services import Services
from org.sleuthkit.autopsy.casemodule.services import FileManager
from org.sleuthkit.autopsy.casemodule.services import Blackboard
'''
Liens utiles :
Certaines fonctions sont inspirees des liens suivant : 

http://www.qnx.com/developers/docs/6.5.0/index.jsp?topic=%2Fcom.qnx.doc.neutrino%2Fbookset.html
https://nop.ninja/ (Matthew Evans)
https://github.com/ReFirmLabs/binwalk/issues/365
https://www.kernel.org/doc/html/latest/filesystems/qnx6.html

'''
#Classe permettant de recuperer les donnees provenant d un systeme de fichier qnx6
class QNX6_FS:

    QNX6_BOOTBLOCK_ZONE = 0
    QNX6_BOOTBLOCK_SIZE = 0x2000
    QNX6_SPBLOCK_SIZE   = 0x200 
    QNX6_SPBLOCK_ZONE   = 0x1000
    QNX6_MAGIC_ID       = 0x68191122
    QNX6_PTR_MAX_LEVELS = 5
    QNX6_SHORT_NAME_MAX = 27
    QNX6_LONG_NAME_MAX = 510

    #Recupere un autopsy abstract file autopsy
    def __init__(self, abstractFile,autopsyLogger):
        self.devQNX6 = abstractFile
        self.logger = autopsyLogger

    #Permet d ecrire un message de log
    def log(self, level, msg):
        self.logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    #Recupere la liste des inodes a partir des 16 root nodes
    def getInodesFromRootNodes(self,listIndBlocks, tailleBlock, offset, level):
        inodeTree = {}
        buff = jarray.zeros( tailleBlock, "b")
        #On lit les pointeurs jusqu a arriver au niveau 0 
        for lvl in range(level,0,-1):
            listIndBlocksTMP = []
            for indiceBlock in listIndBlocks:
                 if(self.checkQNX6ptr(indiceBlock)):
                    ptr = indiceBlock * tailleBlock + offset
                    self.devQNX6.read(buff,ptr,tailleBlock)
                    listIndBlocksTMP  += list(unpack('<'+str(tailleBlock//4)+'I', buff))
            listIndBlocks = deepcopy(listIndBlocksTMP)
        #Des qu on arrive au niveau des inodes entries on lit tailleBlock/128 inodes entries par block
        nbInode = int(tailleBlock/128)
        for indiceBlock in listIndBlocks:
            ptr = indiceBlock * tailleBlock + offset
            self.devQNX6.read(buff,ptr,tailleBlock)
            for i in range(0,nbInode):
                try:
                    inodeTree[len(inodeTree)+1] = self.parseInodeEntry(buff[i*128:(i+1)*128])
                except:
                    inodeTree[len(inodeTree)+1] = None
                    break
        return inodeTree

    #Recupere l arboresence de fichiers et repertoires a parti du premier inode qui corespond au dossier racine
    def getDirTree(self,inodeTree,backUpInodeTree,longNameTree,blocksize,offset):
        delCmp = -1
        dirTree = {}
        buff = jarray.zeros( 32, "b")
        inodeEntryIdList = []
        #Premier Inode = repertoire racine 
        inodeEntryIdList.append(1)
        while(inodeEntryIdList): #Tant qu il reste des dossiers a traiter dans l arboresence
            cInodeId = inodeEntryIdList.pop(0)
            InodeEntry = inodeTree[cInodeId]
            #Si l inode est un repertoire
            if((InodeEntry != None) and (self.InodeEntry_ISDIR(InodeEntry['mode']))):
                objects = []
                #Pour chaque pointeur de l inode on calcul l adresse du block
                for indPtr in range(0,len(InodeEntry['block_ptr'])):
                    ptr = InodeEntry['block_ptr'][indPtr]
                    if(ptr != 0xffffffff):
                        addr = ptr * blocksize + offset
                        #Pour chaque block on lit les 32 repertoires ou fichiers
                        for i in range(0,blocksize/32):
                            obj = self.getDataInodeId( addr+(i*32),longNameTree)
                            #Si l id de l inode est egale a 0 c est que le lien vers les donnees a disparu il s agit probablement d un fichier ou dossier supprime
                            if(obj['PTR'] == 0l or obj['PTR'] == 0): 
                                #Dans ce cas la on lit le meme inode mais dans le backUpInodeTree grace a l id de l inode courant puis on lit le meme pointeurque le courant
                                newAddr = backUpInodeTree[cInodeId]['block_ptr'][indPtr] * blocksize + offset
                                obj = self.getDataInodeId(newAddr+(i*32),longNameTree,"deleted-")
                                if(obj['PTR'] == 0l or obj['PTR'] == 0): #Si le pointeur est toujours egale a 0 on essaie une autre methode pour retrouver l id du contenu supprime
                                    obj = self.getDataInodeId(addr+(i*32)+blocksize,longNameTree,"deleted-") #On recherche si le lien ne se trouve pas blocksize octets plus loins
                                    if(obj['PTR'] == 0xffffffff or obj['PTR'] not in inodeTree or  inodeTree[obj['PTR']] == None or inodeTree[obj['PTR']]['status'] != 2):
                                        continue

                            objects.append(obj)
                #L objet ayant pour nom "."" correspond au repertoire parent
                for obj in objects:
                    if(obj['Name'] == "."):
                        rootID=obj['PTR'] #Recupere l id du repertoire parent
                        break;
                #Pour chaque objets on cree un element du dictionnaire identifie par l id de l inode pointant vers les donnes de l objet, le  nom de l objet et l id du repertoire parent
                for obj in objects: 
                    if((obj['Name'] != "..") and (obj['Name'] != ".") and (obj['Name'] != "") and (obj['Name'] != "") ):
                        dirTree[ obj['PTR'] ] = {'Name':obj['Name'],'ROOT_INODE':rootID}
                        if obj['PTR'] >= 1:
                            inodeEntryIdList.append(obj['PTR'])
                    
        return dirTree
    #Recupere le nom de l objet et l id de l inode pointant vers les donnes de l objet
    def getDataInodeId(self,addr,longNameTree,namePrefix= "") :
        obj = {}
        buff = jarray.zeros( 32, "b")
        self.devQNX6.read(buff,addr,32)
        obj['PTR'] = unpack('<I', buff[0:4])[0]
        if(unpack('<B', buff[4:5])[0]<=self.QNX6_SHORT_NAME_MAX): #Les fichiers longs sont traites differement
             obj['Name'] = namePrefix +("".join("%c" % i for i in unpack('<27B', buff[5:32] ) ).replace("\x00",""))
        else:
            longnameKey = unpack('>I', buff[5:9])[0]+1
            if(longnameKey in longNameTree):
                 obj['Name'] = namePrefix+longNameTree[unpack('>I', buff[5:9])[0]+1] #self.LongNames[unpack('<I', raw[12:16])[0]] 
                #elif(unpack('<I', buff[12:16])[0] in longNameTree):
                #    objects[str(ptr)+"-"+str(i)]['Name'] =  longNameTree[unpack('<I', buff[12:16])[0] ] #self.LongNames[unpack('<I', raw[12:16])[0]]
            else: #Si un fichier avec un nom long a ete supprime alors  on le nomme noname
                obj['Name'] = namePrefix+"noname"
        return obj
    #Pour chaque objet dans le dirTree on recupere les donnes de l objet grace a l inode tree
    def getDirsAndFiles(self,inodeTree,dirTree,blksize=1024,blkOffset=0):
        dirList = []
        fileList = []
        for keyObj in dirTree: #Pour chaque objet dans le dirTree on recupere les donnes de l objet grace a l inode tree
            if(keyObj > 0l): 
                if(inodeTree[keyObj] != None and self.InodeEntry_ISDIR(inodeTree[keyObj]['mode']) ): #Il s agit d un repertoire
                    dirList.append(self.getDirFromInodeId(inodeTree,dirTree,keyObj))
                    continue
                if(inodeTree[keyObj] != None and not self.InodeEntry_ISDIR(inodeTree[keyObj]['mode']) ): #Il s agit d un fichier
                    fileList.append(self.getFileFromInodeId(inodeTree,dirTree,keyObj,blksize,blkOffset))

        return dirList,fileList

    #Recupere les fichiers supprimes dont on ne peut plus recuperer le path et le name
    def getDeletedContent(self,delFilesDirName,inodeTree,dirTree,blksize=1024,blkOffset=0):
        deletedFiles = []
        for IEidx in inodeTree:
            IE = inodeTree[IEidx]
            if(IE != None and IE["status"] == 2 and IEidx not in dirTree): #Si le status est egale a 2 alors il s agit d un element supprime
                if(not self.InodeEntry_ISDIR(IE['mode']) ): #Si c est un fichier
                    #On recupere la liste des pointeurs pointant vers les donnees
                    PhysicalPTRs = []
                    for pointer_index in IE['block_ptr']:
                        if pointer_index != 0xffffffff:
                            #On recupere la liste des pointeurs pointant vers les donnees
                            PhysicalPTRs += [(pointer_index*blksize)+blkOffset]
                    #Recupere les donnees a partir des pointeurs
                    data = self.getDataFromPTR(PhysicalPTRs,IE,IE['filelevels'],blksize,blkOffset)
                    deletedFiles.append({'path':delFilesDirName,'name': str("deleted_")+str(IEidx)  ,'size':IE['size'],'uid':IE['uid'],'gid':IE['gid'],'ftime':IE['ftime'],'atime':IE['atime'],'ctime':IE['ctime'],'mtime':IE['mtime'],'status':IE['status'],'data': data})
        return deletedFiles

    #Recupere les infos du repertoire
    def getDirFromInodeId(self, inodeTree,dirTree,DataINodeID):
        InodeDataEntry = inodeTree[DataINodeID]
        if(InodeDataEntry != None and self.InodeEntry_ISDIR(InodeDataEntry['mode']) ): #Verifie que l inode correspond bien a un repertoire
            dirpath = ""
            dirID = DataINodeID
            while True: #On recupere le path du repertoire
                if(dirID <= 0x01):
                    break
                if(dirID != DataINodeID):
                    dirpath = dirTree[dirID]['Name'] +"//"+ dirpath
                dirID = dirTree[dirID]['ROOT_INODE']

            return {'path':dirpath,'name': dirTree[DataINodeID]['Name']  ,'size':InodeDataEntry['size'],'uid':InodeDataEntry['uid'],'gid':InodeDataEntry['gid'],'ftime':InodeDataEntry['ftime'],'atime':InodeDataEntry['atime'],'ctime':InodeDataEntry['ctime'],'mtime':InodeDataEntry['mtime'],'status':InodeDataEntry['status']} 
        return None

    def getFileFromInodeId(self, inodeTree,dirTree,DataINodeID,blksize=1024,blkOffset=0):
        InodeDataEntry = inodeTree[DataINodeID]
        if(InodeDataEntry != None and not self.InodeEntry_ISDIR(InodeDataEntry['mode']) ):
            filename = dirTree[DataINodeID]['Name']
            ## Create DIR List
            dirpath = ""
            dirID = DataINodeID
            while True:
                if(dirID <= 0x01):
                    break
                if(dirID != DataINodeID):
                    dirpath = dirTree[dirID]['Name'] +"//"+ dirpath
                dirID = dirTree[dirID]['ROOT_INODE']
                if(dirID not in dirTree):
                    dirID != 0x01

            ## Create List of all physical blocks
            PhysicalPTRs = []
            for pointer_index in InodeDataEntry['block_ptr']:
                ## Make sure pointer != 0xFFFFFFFF
                if pointer_index != 0xffffffff:
                    ## Calculate Physical Location.
                    PhysicalPTRs += [(pointer_index*blksize)+blkOffset]
            #Recupere les donnees du fichier
            data = self.getDataFromPTR(PhysicalPTRs,InodeDataEntry,InodeDataEntry['filelevels'],blksize,blkOffset)

            return {'path':dirpath,'name': dirTree[DataINodeID]['Name']  ,'size':InodeDataEntry['size'],'uid':InodeDataEntry['uid'],'gid':InodeDataEntry['gid'],'ftime':InodeDataEntry['ftime'],'atime':InodeDataEntry['atime'],'ctime':InodeDataEntry['ctime'],'mtime':InodeDataEntry['mtime'],'status':InodeDataEntry['status'],'data': data}
        return None

    #Recupere les donnees a partir d une liste de pointeurs
    def getDataFromPTR(self,ptrs,InodeDataEntry,level,blksize,blkOffset):
        DATABUFF = ""
        #Pour chaque pointeur
        for i in range(0,len(ptrs)):
            if level == 0: #Des que les pointeurs sont de niveau 0
                if self.checkQNX6ptr(ptrs[i]): #On check que le pointeurs soit valide
                    if ptrs[i] != 0xffffffff and ptrs[i] != 0x0: 
                        if (InodeDataEntry['size']) >= 1024:
                            buf = jarray.zeros( blksize, "b")
                            self.devQNX6.read(buf,ptrs[i],blksize)
                            DATABUFF += buf
                        else:
                            buf = jarray.zeros( (InodeDataEntry['size'] ), "b")
                            self.devQNX6.read(buf,ptrs[i],(InodeDataEntry['size']))
                            DATABUFF += buf
            else:   #On lit les pointeurs qui ne sont pas de niveau 0 et on rapelle la fonction par recursivite avec ces nouveaux pointeurs    
                buf = jarray.zeros(blksize, "b")
                self.devQNX6.read(buf,ptrs[i],blksize) #On lit blocksize octets a partir de ptrs[i]
                newPTRS = unpack('<'+str(blksize/4)+'I', buf) #Un block contient blocksize/4 pointeurs. taille d un pointeur = 4
                level2_PTRS = []
                for i in range(0,len(newPTRS)):
                    if self.checkQNX6ptr(newPTRS[i]):
                        if newPTRS[i] != 0xffffffff and newPTRS[i] != 0x0:
                            level2_PTRS += [(newPTRS[i]*blksize)+blkOffset] #Calcul de l adresse
                DATABUFF += self.getDataFromPTR(level2_PTRS,InodeDataEntry,level-1,blksize,blkOffset)  #On rappelle la fonction par recusrivite jusqu a avoir des pointeurs de niveau 0
                
        return DATABUFF

    #Fonction provenant de https://github.com/ReFirmLabs/binwalk/issues/365 - https://nop.ninja/ (Matthew Evans)
    def getLongFileNames(self,superBlock):
        longnames = []
        for n in range(0, 16):
            ptr = superBlock['Longfile']['ptr'][n]
            if(self.checkQNX6ptr(ptr)):
                ptrB = (ptr*superBlock['tailleBlock'])+superBlock['SB_end'];
                longnames.append(self.parseQNX6LongFilename(ptr,superBlock['Longfile']['level'],superBlock['tailleBlock'],superBlock['SB_end']))   
        ##Make Dictionary with all Names and INode/PTRs
        count = 1
        Dict = {}
        for i in longnames:
            if(i != None):
                for q in i:
                    if(q != None):
                        Dict[count] = i[q]
                        count = count + 1;
        return Dict
    #Fonction provenant de https://github.com/ReFirmLabs/binwalk/issues/365 - https://nop.ninja/ (Matthew Evans)
    def parseQNX6LongFilename(self,ptr_,level,blksize,blksOffset):
        handle = jarray.zeros( 512, "b")
        self.devQNX6.read(handle,(ptr_*blksize)+blksOffset,512)
        LogFilenameNode={}
        if level == 0:
            size = unpack('<H',handle[0:2])
            fname = unpack('<'+str(size[0])+'B',handle[2:size[0]+2])
            if(size[0] > 0):
                LogFilenameNode[str(ptr_)] = str("".join("%c" % i for i in fname )).strip()
                return LogFilenameNode
            else:
                return None
        else:
            Pointers = unpack('<128I', handle)
            for i in range(0, 128):
                if (self.checkQNX6ptr(Pointers[i]) != False):
                    name = (self.parseQNX6LongFilename(Pointers[i],level-1,blksize,blksOffset))
                    if name != None:
                        if level >= 1:
                            LogFilenameNode[str(Pointers[i])]=name[str(Pointers[i])]
                        else:
                            LogFilenameNode[str(Pointers[i])]=name
        return LogFilenameNode
    #Lit le super block commencant a l offset
    def readSuperBlock(self, offset = 0):
        buffer = jarray.zeros( self.QNX6_SPBLOCK_SIZE, "b")
        self.devQNX6.read(buffer,offset,self.QNX6_SPBLOCK_SIZE)
        spBlock = {}
        spBlock["magic"] = unpack('<I', buffer[:4])[0]
        spBlock['checksum'] = (unpack('>I', buffer[4:8])[0])
        spBlock['serialNum'] = unpack('<Q', buffer[8:16])[0]
        spBlock['ctime'] = unpack('<I', buffer[16:20])[0]
        spBlock['atime'] = unpack('<I', buffer[20:24])[0]
        spBlock['flags'] = unpack('<I', buffer[24:28])[0]
        spBlock['v1'] = unpack('<H', buffer[28:30])[0]
        spBlock['v2'] = unpack('<H', buffer[30:32])[0]
        spBlock['volumeid'] = unpack('<16B', buffer[32:48])
        spBlock['tailleBlock'] = unpack('<I', buffer[48:52])[0]
        spBlock['nbInodes'] = unpack('<I', buffer[52:56])[0]
        spBlock['nbInodesLibres'] = unpack('<I', buffer[56:60])[0]
        spBlock['nbBlocks'] = unpack('<I', buffer[60:64])[0]
        spBlock['nbBlocksLibres'] = unpack('<I', buffer[64:68])[0]
        spBlock['allocgroup'] = unpack('<I', buffer[68:72])[0]
        spBlock['SB_end'] = offset + self.QNX6_SPBLOCK_ZONE;
        spBlock['RootNode'] = self.parseQNX6RootNode(buffer[72:152])
        spBlock['Bitmap'] = self.parseQNX6RootNode(buffer[152:232])
        spBlock['Longfile'] = self.parseQNX6RootNode(buffer[232:312])
        return spBlock
    #Parse le root node se trouvant dans les super blocks
    def parseQNX6RootNode(self,rn):
        RN = {}
        RN['size'] = unpack('<Q', rn[0:8])[0]
        RN['ptr'] = unpack('<16I', rn[8:72])
        RN['level'] = unpack('<B', rn[72:73])[0]
        RN['mode'] = unpack('<B', rn[73:74])[0]
        RN['reserved'] = unpack('<6B', rn[74:80])[0]
        return RN 
    #Inode de niveau 0 contenant les donnees des fichiers ou repertoires ainsi que les pointeurs vers les donnees
    def parseInodeEntry(self,ie): #qnx6_inode_entry 128bytes
        IE = {}
        IE['size'] = unpack('<Q',ie[0:8])[0]
        IE['uid'] = unpack('<I',ie[8:12])[0]
        IE['gid'] = unpack('<I',ie[12:16])[0]
        IE['ftime'] = unpack('<I',ie[16:20])[0]
        IE['mtime'] = unpack('<I',ie[20:24])[0]
        IE['atime'] = unpack('<I',ie[24:28])[0]
        IE['ctime'] = unpack('<I',ie[28:32])[0]

        IE['mode'] = unpack('<H',ie[32:34])[0]
        IE['ext_mode'] = unpack('<H',ie[34:36])[0]
        IE['block_ptr'] = unpack('<16I',ie[36:100])
        IE['filelevels'] = unpack('<B',ie[100:101])[0]
        IE['status'] = unpack('<B',ie[101:102])[0]
        IE['unknown2'] = unpack('<2B',ie[102:104])
        IE['zero2'] = unpack('<6I',ie[104:128]) 
        if(IE['size'] == 0):
                return None 
        return IE
    #Permet d identifier que le FS est bien un QNX6 a partir du numero magic contenu dans le super block
    def isQNX6FS(self,SP):
        return (SP["magic"] == self.QNX6_MAGIC_ID)
    def InodeEntry_ISDIR(self,mode):
        return ((mode & 040000) == 040000)
    def InodeEntry_ISREG(self,mode):
        return ((mode & 0100000) == 0100000)
    def InodeEntry_ISLNK(self,mode):
        return ((mode & 0120000) == 0120000)
    #Recupere l offset du second super block a partir du premier super block
    def getSndSPBlockOffset(self, SB):
        return SB['SB_end'] + ( SB['nbBlocks'] * SB['tailleBlock'])
    def checkQNX6ptr(self,ptr):
        return not ((ptr+1) & ptr == 0 and ptr != 0)

