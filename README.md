
Specifications
======

_Research into the QNX6 file system in order to develop an Autopsy module to recover data (Full report in French ):_  [QNX6_FileSystem_FullReport_FR](https://github.com/jdbonfils/QNX6-Files-System-Reader-Ingest-Module/blob/master/QNX6_FileSystem_FullReport_FR.pdf)


This module has been developped for the forensic software Autopsy. It is able to recover data from a QNX6 device and generate the original file tree. It can also recover some deleted files from devices as well. For the time being, the whole image can not be passed to the module. It is necessary at first to extract the partitions.

**Autopsy is required to run this module :** [[Autopsy | Digital Forensics](https://www.autopsy.com/)]

In Autopsy, **"Unallocated space image file"** must be selected as type of data source in order to run the ingest module properly

Installation
======

Unzip the project archive in \autopsy\python_modules directory. At startup autopsy should detect the ingest module and it should be visible on the user interface as such:

<img src="/images/QNX6IngestModule.png" style="float: left; margin-right: 10px;" />

More information to install python ingest modules: [Autopsy User Documentation: Installing 3rd-Party Modules (sleuthkit.org)](http://sleuthkit.org/autopsy/docs/user-docs/4.18.0/module_install_page.html)


Usage
======

### [Ingest module presentation :](http://www.youtube.com/watch?feature=player_embedded&v=H9FppPDLrpY)
<a href="http://www.youtube.com/watch?feature=player_embedded&v=H9FppPDLrpY
" target="_blank"><img src="http://img.youtube.com/vi/H9FppPDLrpY/0.jpg" 
alt="Inegst module presentation" width="240" height="180" border="10" /></a>

### Main features
- **Get file system metadata**
<img src="images/fsMetaData.JPG" style="float: left; margin-right: 10px;" />

- **Get files and directories metadata**
<img src="images/filesmetadata.JPG"  style="float: left; margin-right: 10px;" />

- **Recover the original file tree**
<img src="images/fileTree.JPG"  style="float: left; margin-right: 10px;" />

- **Recover some files that have been deleted from the file system**
<img src="images/deletedFiles.JPG" style="float: left; margin-right: 10px;" />

- **Files are extracted into : \AutosyCaseName\ModuleOutput\DataSourceName\PartitionX**
<img src="images/output.JPG"  style="float: left; margin-right: 10px;" />

- **Other ingest module ca be run on the extracted data**

References
======

Special thanks to these projects that allowed me to develop this ingest module and to understand the QNX6 file system: 

[nop.ninja - Mathew Evans](https://nop.ninja/)

[Snapshot of the QNX6 filesystem - univ-grenoble-alpes ](https://gricad-gitlab.univ-grenoble-alpes.fr/jonglezb/linux-kaunetem/-/tree/505a666ee3fc611518e85df203eb8c707995ceaa/fs/qnx6)
