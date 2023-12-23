#pragma once
#include<iostream>
#include <ws2tcpip.h>
#include "pcap.h"
#include "winsock2.h"
#include "stdio.h"
#pragma comment(lib,"ws2_32.lib")//表示链接的时侯找ws2_32.lib
#pragma warning( disable : 4996 )//要使用旧函数
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define RT_TABLE_SIZE 256   //路由表大小
using namespace std;
#pragma pack(1)//以1byte方式对齐
//路由表结构
typedef struct router_table {
	ULONG netmask;         //网络掩码
	ULONG desnet;          //目的网络
	ULONG nexthop;         //下一站路由
}router_table;
typedef struct FrameHeader_t//帧首部
{
	BYTE DesMac[6];
	BYTE SrcMac[6];
	WORD FrameType;
}FrameHeader_t;
typedef struct IPHeader_t {		//IP首部
	BYTE	Ver_HLen;   //版本与协议类型
	BYTE	TOS;        //服务类型
	WORD	TotalLen;   //总长度
	WORD	ID;         //标识
	WORD	Flag_Segment; //标志和片偏移
	BYTE	TTL;        //生存周期
	BYTE	Protocol;   //协议
	WORD	Checksum;   //校验和
	ULONG	SrcIP;      //源IP地址
	ULONG	DstIP;      //目的IP地址
} IPHeader_t;

typedef struct IPData_t {	//包含帧首部和IP首部的数据包
	FrameHeader_t	FrameHeader;
	IPHeader_t		IPHeader;
} IPData_t;

typedef struct ARPFrame_t//ARP帧
{
	FrameHeader_t FrameHeader;
	WORD HardwareType;
	WORD ProtocolType;
	BYTE HLen;
	BYTE PLen;
	WORD Operation;
	BYTE SendHa[6];
	DWORD SendIP;
	BYTE RecvHa[6];
	DWORD RecvIP;
}ARPFrame_t;

#pragma pack()//恢复对齐方式

//选路 实现最长匹配
ULONG search(router_table* t, int tLength, ULONG DesIP)//返回下一跳步的IP
{
	ULONG best_desnet = 0;  //最优匹配的目的网络
	int best = -1;   //最优匹配路由表项的下标
	for (int i = 0; i < tLength; i++)
	{
		if ((t[i].netmask & DesIP) == t[i].desnet) //目的IP和网络掩码相与后和目的网络比较
		{
			if (t[i].desnet >= best_desnet)//最长匹配
			{
				best_desnet = t[i].desnet;  //保存最优匹配的目的网络
				best = i;    //保存最优匹配路由表项的下标
			}
		}
	}
	if (best == -1)
		return 0xffffffff;      //没有匹配项
	else
		return t[best].nexthop;  //获得匹配项
}
//向路由表中添加项（没有做插入时排序的优化）
bool additem(router_table* t, int& tLength, router_table item)
{
	if (tLength == RT_TABLE_SIZE)  //路由表满则不能添加
		return false;
	for (int i = 0; i < tLength; i++)
		if ((t[i].desnet == item.desnet) && (t[i].netmask == item.netmask) && (t[i].nexthop == item.nexthop))   //路由表中已存在该项，则不能添加
			return false;
	t[tLength] = item;   //添加到表尾
	tLength = tLength + 1;
	return true;
}
//从路由表中删除项
bool deleteitem(router_table* t, int& tLength, int index)
{
	if (tLength == 0)   //路由表空则不能删除
		return false;
	for (int i = 0; i < tLength; i++)
		if (i == index)   //删除以index索引的表项
		{
			for (; i < tLength - 1; i++)
				t[i] = t[i + 1];
			tLength = tLength - 1;
			return true;
		}
	return false;   //路由表中不存在该项则不能删除
}

void printIP(ULONG IP)
{
	BYTE* p = (BYTE*)&IP;
	for (int i = 0; i < 3; i++)
	{
		cout << dec << (int)*p << ".";
		p++;
	}
	cout << dec << (int)*p << " ";
}

void printMAC(BYTE MAC[])//打印mac
{
	for (int i = 0; i < 5; i++)
		printf("%02X-", MAC[i]);
	printf("%02X\n", MAC[5]);
}
//打印路由表
void print_rt(router_table* t, int& tLength)
{
	for (int i = 0; i < tLength; i++)
	{
		cout << "\t网络掩码\t" << "目的网络\t" << "下一站路由\t" << endl;
		cout << i << "  ";
		printIP(t[i].netmask);
		printIP(t[i].desnet);
		printIP(t[i].nexthop);
		cout << endl;
	}
}

void setchecksum(IPData_t* temp)//设置校验和
{
	temp->IPHeader.Checksum = 0;
	unsigned int sum = 0;
	WORD* t = (WORD*)&temp->IPHeader;//每16位为一组
	for (int i = 0; i < sizeof(IPHeader_t) / 2; i++)
	{
		sum += t[i];
		while (sum >= 0x10000)//如果溢出，则进行回卷
		{
			int s = sum >> 16;
			sum -= 0x10000;
			sum += s;
		}
	}
	temp->IPHeader.Checksum = ~sum;//结果取反
}

bool checkchecksum(IPData_t* temp)//检验
{
	unsigned int sum = 0;
	WORD* t = (WORD*)&temp->IPHeader;
	for (int i = 0; i < sizeof(IPHeader_t) / 2; i++)
	{
		sum += t[i];
		while (sum >= 0x10000)//包含原有校验和一起进行相加
		{
			int s = sum >> 16;
			sum -= 0x10000;
			sum += s;
		}
	}
	if (sum == 65535)//源码+反码-》全1
		return 1;//校验和正确
	return 0;
}
