CMSC 626
Peer to Peer Distributed File System with Encryption

Team Members

● Bhavani Shankar Mahamkali (AP70853)

● Samritha Balam (ZZ46412)

● Rama Sai Mamidala (TS45052)

● Srichand Medagani (EF69050)

Abstract

In this project we have built a peer to peer distributed file system which is encrypted
with the Fernet algorithm. This is a file system in which users can create, read, write,
delete and restore files with certain permissions. Also for duplicacy, the replicas of the
files are maintained on at least 3 peers in encrypted format. It also allows the peers to
share files between them securely without any intruder disturbing the integrity of files as
the names of the files, content and even the communication between the peers is
encrypted. Furthermore, multiple users can simultaneously perform operations while
maintaining the ACID properties.

Tools and Libraries Used: Microsoft VS code, Python IDLE, Fernet, Socket

Introduction

In this system, the Central Directory Server(CDS) maintains all the information of the
peers and handles the CRUD operations of the files concurrently. Each peer in this P2P
file system acts as both client and server where the communication is bidirectional. A
peer can initiate the CRUD operations after being authorized by the CDS. A peer can
create, read, write, delete and restore files in this Distributed File System (DFS). The
names of the files, directories, content of the files and the communication between the
peers are encrypted in order to build a secure and confidential file system. If any
unauthorized user makes any malicious activity on the files or the directories, the
system detects and reports the issue to all the authorized users of the modified files or
the directories. File locking will be possible to avoid race conditions among peers.

Working

● CDS acts as the master server which maintains every detail (as depicted in the
block diagram A) of the file system.

● Whenever a new peer registers on CDS, the IP address and the port number will
be saved as a data structure and the peer gets added under its active-peers
directory.

● After the peer gets registered, a bin gets created for its storage as shown in the
below figure A.

● If a file is created by any of the peers connected to this system, the file is saved
in the bins of that particular peer and the replicas of the file are created in each
and every peer connected to that file system.

● The files are saved with certain attributes for management purposes.

● There are few attributed maintained by the CDS per each file after it gets created
by a peer, which are, “The Owner (peer which creates the file), access
Permissions, replicated-peers, encryption Key, lock, deleted”, are the attributes of
a file in CDS to provide services for all the peers in the File System.

● The access permissions are saved as the following enumerated values,
(1: read and write, 2: read only, 3: restricted), where the restricted files are only
seen by the owner of the file.

● To manage concurrent users we use “Lock” which is a boolean value.

● Replicated Processes stores the names of the peers which contain the file.

● Each file has its own encryption key which is the only way to access the file (this
provides security to the file).

● If a file is in use, the other peer which asks the CDS for the same file gets the
message that “the file is being used by another peer” if we use the Lock as an
attribute.

● Whenever a peer wants to access a file to perform any of the supported file
operations, it sends a request to CDS.

● CDS will now look into the file system permissions and check whether the peer is
authorized to perform the requested operation.

● Later, if the peer has the required permissions the CDS provides the IP address
and the port number of all the peers which have the replica of the file along with
its encryption key.

● The user (peer that requests file) tries to establish connection to one of the peers
that contains the file replica (corresponding to the encryption key) and an error
message gets generated for every bad connection.

● For all the above data transactions the messages/requests/responses containing
the body is encrypted using Fernet encryption algorithm that is based on 128-bit
AES keys and a common encryption-decryption key.

● After a connection gets established between two peers, a file corresponding to
the encryption key sent by the user is shared.

● There exists a decryption block based on Fernet encryption algorithm to decrypt
the file shared to the user.

Starting of the Servers and Connections:

We will first run the CDS followed by the peers, peer IP Addresses and the port number
(In the form of a data structure), that gets saved on CDS.

Operations Involved:

Create:

Command: touch filename.txt [Access Permission]

Concept of Operation: Whenever a peer sends a create request to CDS, the file will be
created with certain attributes like owner, access permissions, replicated processes,
lock, encryption key. These attributes are the key in this file sharing environment. The
replicas of the file are created in every peer in encrypted form.

Read:

Command: read filename.txt

Concept of Operation: Peer1 wants to read a file (filename.txt) and this request is sent
to the CDS and now CDS will check whether the user is authorized and check whether
the user has the read permission and if it has the read permission it provides the IP
Address and Port number of Peer2 (Peer2 has the file which is asked by Peer1). The
Encryption Key will also be provided by the CDS to Peer1 to access the file.

Write operation:

Command: cat filename.txt

Concept of Operation: Whenever this request is made by any of the peers, CDS checks
the access permission given by the owner and if the owner has created the file in write
mode, then CDS provides the encryption key along with the details of the peer which
has the requested file. After the peer finishes the writing, the changes that are made will
be replicated on every peer.

Delete operation:

Command: rm filename.txt

Concept of Operation: A peer with write permission can also delete a file with the above
command and the replicas are deleted at every peer but the master copy resists at the
owner peer which is used for restoration. Even the owner can’t access the file while it is
deleted.

Restore operation:

Command: restore filename.txt

Concept of Operation: If a peer wants to restore a file, then the file will be replicated to
all the peers from the master copy which resides at the owner peer.

Create Directory:

Command: touch directory name [Access Permission]

Concept of Operation: Whenever a peer wants to create a directory, CDS will be
creating a directory with certain attributes used for the management of the directory.

Delete Directory:

Command: delete directory name

Concept of Operation: The directory can be deleted by any peer and it will be deleted at
every peer but resides at owner (which cannot be accessed by owner) for restoring the
directory.

Conclusion:

The current DFS is contained with all the features required for a robust peer to peer
(P2P) based distributed file system with Fernet encryption. We have tested the current
DFS scaled across 4 peers with all the CRUD operations required and also tested for
the peer being able to host multiple files in the bin with different extensions without the
need to change the code. Overall, we all enjoyed working on this project with a great
learning curve
