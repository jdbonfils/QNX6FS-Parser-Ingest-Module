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


class QNX6_FS:

    QNX6_BOOTBLOCK_ZONE = 0
    QNX6_SPBLOCK_SIZE   = 0x200 
    QNX6_SPBLOCK_ZONE   = 0x1000
    QNX6_MAGIC_ID       = 0x68191122
    QNX6_PTR_MAX_LEVELS = 5
    QNX6_SHORT_NAME_MAX = 27

    def __init__(self, abstractFile):
        self.devQNX6 = abstractFile
        self.spBlock = self.readSPBlock()
        

    def ParseQNX(self, Partition=0, PartitionID=0):

        ## If the blocksize != 512, then super block is longer, re-read the area.
        #if (SuperBlock['blocksize'] != 512):
        #    self.fileIO.seek( ( Partition['StartingOffset'] + self.QNX6_BOOTBLOCK_SIZE ) , 0 )
        #    Data = self.fileIO.read( SuperBlock['blocksize'] )
        #    SuperBlock = self.parseQNX6SuperBlock(Data, Partition['StartingOffset'])

       

            #self.parseBitmap(SB)
            #self.LongNames = self.parseLongFileNames(SB)


            return 0

    def checkQNX6ptr(self,ptr):
        return not ((ptr+1) & ptr == 0 and ptr != 0)

    def readBlockPointers(self,listIndBlocks, tailleBlock, offset, level):
        inodeTree = {}
        buff = jarray.zeros( tailleBlock, "b")
        for lvl in range(level,0,-1):
            listIndBlocksTMP = []
            for indiceBlock in listIndBlocks:
                 if(self.checkQNX6ptr(indiceBlock)):
                    ptr = indiceBlock * tailleBlock + offset
                    self.devQNX6.read(buff,ptr,tailleBlock)
                    listIndBlocksTMP  += list(unpack('<'+str(tailleBlock//4)+'I', buff))
            listIndBlocks = deepcopy(listIndBlocksTMP)
        nbInode = int(tailleBlock/128)
        for indiceBlock in listIndBlocks:
            ptr = indiceBlock * tailleBlock + offset
            self.devQNX6.read(buff,ptr,tailleBlock)
            for i in range(0,nbInode):
                try:
                    inodeTree[len(inodeTree)+1] = self.readQNX6Lvl0Inode(buff[i*128:(i+1)*128])
                except:
                    inodeTree[len(inodeTree)+1] = None
                    break
        return inodeTree

    def parseINodeDIRStruct(self,inodeTree,blocksize,offset):
        dirTree = {}
        buff = jarray.zeros( 32, "b")
        inodeEntryList = []
        #Inode repertoire racine 
        inodeEntryList.append(inodeTree[1])
        while(inodeEntryList):
            InodeEntry = inodeEntryList.pop(0)
            if((InodeEntry != None) and (self.InodeEntry_ISDIR(InodeEntry['mode']))):
                objects = {}
                for ptr in InodeEntry['block_ptr']:
                    if(ptr != 0xffffffff):
                        addr = ptr * blocksize + offset
                        for i in range(0,blocksize/32):
                            self.devQNX6.read(buff,addr+(i*32),32)
                            objects[str(ptr)+"-"+str(i)]={}
                            objects[str(ptr)+"-"+str(i)]['PTR'] = unpack('<I', buff[0:4])[0]
                            if(unpack('<B', buff[4:5])[0]<=self.QNX6_SHORT_NAME_MAX):
                                objects[str(ptr)+"-"+str(i)]['Name'] = "".join("%c" % i for i in unpack('<27B', buff[5:32] ) ).replace("\x00","")
                            else:   
                                objects[str(ptr)+"-"+str(i)]['Name'] =  self.LongNames[unpack('>I', buff[5:9])[0]+1] #self.LongNames[unpack('<I', raw[12:16])[0]] 
                for i in objects:
                    if(objects[i]['Name'] == "."):
                        rootID=objects[i]['PTR']
                        break;
                for i in objects:
                    obj = objects[i]
                    if((obj['Name'] != "..") and (obj['Name'] != ".") and (obj['Name'] != "")):
                        dirTree[ obj['PTR'] ] = {'Name':obj['Name'],'ROOT_INODE':rootID}
                        ##Recursively Process all Dirs
                        if obj['PTR'] > 1:
                            inodeEntryList.append(inodeTree[obj['PTR']])
        return dirTree,inodeTree
   
    def genDirs(self,outputDir, inodeTree,dirTree,DataINodeID):
        InodeDataEntry = inodeTree[DataINodeID]
        if(InodeDataEntry != None and self.InodeEntry_ISDIR(InodeDataEntry['mode']) ):
            ## Create DIR List
            dirpath = ""
            dirID = DataINodeID
            while True:
                if(dirID <= 0x01):
                    break
                if(dirID != DataINodeID):
                    dirpath = dirTree[dirID]['Name'] +"//"+ dirpath
                dirID = dirTree[dirID]['ROOT_INODE']
            return {'path':dirpath,'name': dirTree[DataINodeID]['Name']  ,'size':InodeDataEntry['size'],'uid':InodeDataEntry['uid'],'gid':InodeDataEntry['gid'],'ftime':InodeDataEntry['ftime'],'atime':InodeDataEntry['atime'],'ctime':InodeDataEntry['ctime'],'mtime':InodeDataEntry['mtime'],'status':InodeDataEntry['status']} 
        return None

    def dumpfile(self,outputDir, inodeTree,dirTree,DataINodeID,blksize=1024,blkOffset=0,PartitionID=0):
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

            ## Create List of all physical blocks
            PhysicalPTRs = []
            for pointer_index in InodeDataEntry['block_ptr']:
                ## Make sure pointer != 0xFFFFFFFF
                if pointer_index != 0xffffffff:
                    ## Calculate Physical Location.
                    PhysicalPTRs += [(pointer_index*blksize)+blkOffset]

            if(os.path.exists(outputDir+"//"+dirpath) == False):
                try: 
                    os.makedirs(outputDir+"//"+dirpath)
                except OSError as e:
                    pass

            filepath=outputDir+"//"+dirpath+filename
            if(os.path.exists(filepath) == False):
                self.batchProcessPTRS(PhysicalPTRs,InodeDataEntry,InodeDataEntry['filelevels'],blksize,blkOffset,filepath)

            os.utime(filepath, (InodeDataEntry['atime'], InodeDataEntry['mtime']))

    def batchProcessPTRS(self,ptrs,InodeDataEntry,level,blksize,blkOffset,path,io=0):
        if io == 0:
            io = open(path,"wb+");

        DATABUFF = ""
        for i in range(0,len(ptrs)):
            if level == 0:
                if self.checkQNX6ptr(ptrs[i]):
                    if ptrs[i] != 0xffffffff and ptrs[i] != 0x0: 
                        if (InodeDataEntry['size'] - io.tell()) >= 1024:
                            buf = jarray.zeros( blksize, "b")
                            self.devQNX6.read(buf,ptrs[i],blksize)
                            DATABUFF += buf
                        else:
                            buf = jarray.zeros( (InodeDataEntry['size'] - io.tell()), "b")
                            self.devQNX6.read(buf,ptrs[i],(InodeDataEntry['size'] - io.tell()))
                            DATABUFF += buf
            else:       
                buf = jarray.zeros(blksize, "b")
                self.devQNX6.read(buf,ptrs[i],blksize)
                newPTRS = unpack('<'+str(blksize/4)+'I', buf)
                level2_PTRS = []
                for i in range(0,len(newPTRS)):
                    if self.checkQNX6ptr(newPTRS[i]):
                        if newPTRS[i] != 0xffffffff and newPTRS[i] != 0x0:
                            level2_PTRS += [(newPTRS[i]*blksize)+blkOffset]
                self.batchProcessPTRS(level2_PTRS,InodeDataEntry,level-1,blksize,blkOffset,path,io)

        if level == 0:
            io.write(DATABUFF)
            io.close()


    def readSPBlock(self, offset=0x2000):
        buffer = jarray.zeros( self.QNX6_SPBLOCK_SIZE, "b")
        self.devQNX6.read(buffer,offset,self.QNX6_SPBLOCK_SIZE)
        spBlock = {}
        spBlock["magic"] = unpack('<I', buffer[:4])[0]
        spBlock['checksum'] = (unpack('>I', buffer[4:8])[0])
        #self.spBlock['checksum_calc'] = zlib.crc32(sb[8:512],0) & 0xFFFFFFFF
        spBlock['serialNum'] = unpack('<Q', buffer[8:16])[0]
        spBlock['ctime'] = unpack('<I', buffer[16:20])[0]
        spBlock['atime'] = unpack('<I', buffer[20:24])[0]
        spBlock['flags'] = unpack('<I', buffer[24:28])[0]
        spBlock['v1'] = unpack('<H', buffer[28:30])[0]
        spBlock['v2'] = unpack('<H', buffer[30:32])[0]
        spBlock['volumeid'] = unpack('<16B', buffer[32:48])
        spBlock['tailleBlock'] = unpack('<I', buffer[48:52])[0]
        spBlock['numRootInodes'] = unpack('<I', buffer[52:56])[0]
        spBlock['rootInodesLibres'] = unpack('<I', buffer[56:60])[0]
        spBlock['numBlocks'] = unpack('<I', buffer[60:64])[0]
        spBlock['blocksLibres'] = unpack('<I', buffer[64:68])[0]
        spBlock['allocgroup'] = unpack('<I', buffer[68:72])[0]
        spBlock['SP_end'] = offset + self.QNX6_SPBLOCK_ZONE;
        spBlock['RootNode'] = self.parseQNX6RootNode(buffer[72:152])
        spBlock['Bitmap'] = self.parseQNX6RootNode(buffer[152:232])
        spBlock['Longfile'] = self.parseQNX6RootNode(buffer[232:312])
        #self.spBlock['Unknown'] = self.parseQNX6RootNode(sb[312:392])
        return spBlock

    def parseQNX6RootNode(self,rn):
        RN = {}
        RN['size'] = unpack('<Q', rn[0:8])[0]
        RN['ptr'] = unpack('<16I', rn[8:72])
        RN['level'] = unpack('<B', rn[72:73])[0]
        RN['mode'] = unpack('<B', rn[73:74])[0]
        RN['reserved'] = unpack('<6B', rn[74:80])[0]
        return RN 

    def readQNX6Lvl0Inode(self,ie): #qnx6_inode_entry 128bytes
        IE = {}
        IE['size'] = unpack('<Q',ie[0:8])[0]
        IE['uid'] = unpack('<I',ie[8:12])[0]
        IE['gid'] = unpack('<I',ie[12:16])[0]
        IE['ftime'] = unpack('<I',ie[16:20])[0]
        IE['mtime'] = unpack('<I',ie[20:24])[0]
        IE['atime'] = unpack('<I',ie[24:28])[0]
        IE['ctime'] = unpack('<I',ie[28:32])[0]
        ###S_IFREG 0100000 S_IFDIR 040000 S_IRUSR 0400 S_IWUSR 0200 S_IXUSR 0100
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

    def isQNX6FS(self,SP):
        return (SP["magic"] == self.QNX6_MAGIC_ID)
    def InodeEntry_ISDIR(self,mode):
        return ((mode & 040000) == 040000)
    def InodeEntry_ISREG(self,mode):
        return ((mode & 0100000) == 0100000)
    def InodeEntry_ISLNK(self,mode):
        return ((mode & 0120000) == 0120000)
    def getFirstSuperBlock(self):
        return  self.spBlock
    def getSndSPBlockOffset(self):
        return self.QNX6_SPBLOCK_ZONE + self.QNX6_BOOTBLOCK_ZONE + ( self.spBlock['numBlocks'] * self.spBlock['tailleBlock'])
