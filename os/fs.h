#ifndef __FS_H__
#define __FS_H__

#include "types.h"

#define NFILE 100
#define NINODE 50
#define NDEV 10
#define ROOTDEV 1
#define MAXOPBLOCKS 10
#define NBUF (MAXOPBLOCKS * 3)
#define FSSIZE 1000
#define MAXPATH 128

#define ROOTINO 1
#define BSIZE 1024

struct superblock {
	uint magic;
	uint size;
	uint nblocks;
	uint ninodes;
	uint inodestart;
	uint bmapstart;
};

#define FSMAGIC 0x10203040

#define NDIRECT 12
#define NINDIRECT (BSIZE / sizeof(uint))
#define MAXFILE (NDIRECT + NINDIRECT)

#define T_DIR 1
#define T_FILE 2

// On-disk inode structure
struct dinode {
	short type;
	short nlink;   // hard link count; uses one pad slot, sizeof(dinode) unchanged
	short pad[2];
	uint size;
	uint addrs[NDIRECT + 1];
};

#define IPB (BSIZE / sizeof(struct dinode))
#define IBLOCK(i, sb) ((i) / IPB + sb.inodestart)
#define BPB (BSIZE * 8)
#define BBLOCK(b, sb) ((b) / BPB + sb.bmapstart)

#define DIRSIZ 14

struct dirent {
	ushort inum;
	char name[DIRSIZ];
};

struct inode;

void fsinit();
int dirlink(struct inode *, char *, uint);
struct inode *dirlookup(struct inode *, char *, uint *);
struct inode *ialloc(uint, short);
struct inode *idup(struct inode *);
void iinit();
void ivalid(struct inode *);
void iput(struct inode *);
void iunlock(struct inode *);
void iunlockput(struct inode *);
void iupdate(struct inode *);
struct inode *namei(char *);
struct inode *root_dir();
int readi(struct inode *, int, uint64, uint, uint);
int writei(struct inode *, int, uint64, uint, uint);
void itrunc(struct inode *);
int dirunlink(struct inode *, char *); // removes a named dirent from a directory
int dirls(struct inode *);
#endif //!__FS_H__