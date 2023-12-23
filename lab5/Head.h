#pragma once
#include<iostream>
#include <ws2tcpip.h>
#include "pcap.h"
#include "winsock2.h"
#include "stdio.h"
#pragma comment(lib,"ws2_32.lib")//��ʾ���ӵ�ʱ����ws2_32.lib
#pragma warning( disable : 4996 )//Ҫʹ�þɺ���
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define RT_TABLE_SIZE 256   //·�ɱ��С
using namespace std;
#pragma pack(1)//��1byte��ʽ����
//·�ɱ�ṹ
typedef struct router_table {
	ULONG netmask;         //��������
	ULONG desnet;          //Ŀ������
	ULONG nexthop;         //��һվ·��
}router_table;
typedef struct FrameHeader_t//֡�ײ�
{
	BYTE DesMac[6];
	BYTE SrcMac[6];
	WORD FrameType;
}FrameHeader_t;
typedef struct IPHeader_t {		//IP�ײ�
	BYTE	Ver_HLen;   //�汾��Э������
	BYTE	TOS;        //��������
	WORD	TotalLen;   //�ܳ���
	WORD	ID;         //��ʶ
	WORD	Flag_Segment; //��־��Ƭƫ��
	BYTE	TTL;        //��������
	BYTE	Protocol;   //Э��
	WORD	Checksum;   //У���
	ULONG	SrcIP;      //ԴIP��ַ
	ULONG	DstIP;      //Ŀ��IP��ַ
} IPHeader_t;

typedef struct IPData_t {	//����֡�ײ���IP�ײ������ݰ�
	FrameHeader_t	FrameHeader;
	IPHeader_t		IPHeader;
} IPData_t;

typedef struct ARPFrame_t//ARP֡
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

#pragma pack()//�ָ����뷽ʽ

//ѡ· ʵ���ƥ��
ULONG search(router_table* t, int tLength, ULONG DesIP)//������һ������IP
{
	ULONG best_desnet = 0;  //����ƥ���Ŀ������
	int best = -1;   //����ƥ��·�ɱ�����±�
	for (int i = 0; i < tLength; i++)
	{
		if ((t[i].netmask & DesIP) == t[i].desnet) //Ŀ��IP����������������Ŀ������Ƚ�
		{
			if (t[i].desnet >= best_desnet)//�ƥ��
			{
				best_desnet = t[i].desnet;  //��������ƥ���Ŀ������
				best = i;    //��������ƥ��·�ɱ�����±�
			}
		}
	}
	if (best == -1)
		return 0xffffffff;      //û��ƥ����
	else
		return t[best].nexthop;  //���ƥ����
}
//��·�ɱ�������û��������ʱ������Ż���
bool additem(router_table* t, int& tLength, router_table item)
{
	if (tLength == RT_TABLE_SIZE)  //·�ɱ����������
		return false;
	for (int i = 0; i < tLength; i++)
		if ((t[i].desnet == item.desnet) && (t[i].netmask == item.netmask) && (t[i].nexthop == item.nexthop))   //·�ɱ����Ѵ��ڸ���������
			return false;
	t[tLength] = item;   //��ӵ���β
	tLength = tLength + 1;
	return true;
}
//��·�ɱ���ɾ����
bool deleteitem(router_table* t, int& tLength, int index)
{
	if (tLength == 0)   //·�ɱ������ɾ��
		return false;
	for (int i = 0; i < tLength; i++)
		if (i == index)   //ɾ����index�����ı���
		{
			for (; i < tLength - 1; i++)
				t[i] = t[i + 1];
			tLength = tLength - 1;
			return true;
		}
	return false;   //·�ɱ��в����ڸ�������ɾ��
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

void printMAC(BYTE MAC[])//��ӡmac
{
	for (int i = 0; i < 5; i++)
		printf("%02X-", MAC[i]);
	printf("%02X\n", MAC[5]);
}
//��ӡ·�ɱ�
void print_rt(router_table* t, int& tLength)
{
	for (int i = 0; i < tLength; i++)
	{
		cout << "\t��������\t" << "Ŀ������\t" << "��һվ·��\t" << endl;
		cout << i << "  ";
		printIP(t[i].netmask);
		printIP(t[i].desnet);
		printIP(t[i].nexthop);
		cout << endl;
	}
}

void setchecksum(IPData_t* temp)//����У���
{
	temp->IPHeader.Checksum = 0;
	unsigned int sum = 0;
	WORD* t = (WORD*)&temp->IPHeader;//ÿ16λΪһ��
	for (int i = 0; i < sizeof(IPHeader_t) / 2; i++)
	{
		sum += t[i];
		while (sum >= 0x10000)//������������лؾ�
		{
			int s = sum >> 16;
			sum -= 0x10000;
			sum += s;
		}
	}
	temp->IPHeader.Checksum = ~sum;//���ȡ��
}

bool checkchecksum(IPData_t* temp)//����
{
	unsigned int sum = 0;
	WORD* t = (WORD*)&temp->IPHeader;
	for (int i = 0; i < sizeof(IPHeader_t) / 2; i++)
	{
		sum += t[i];
		while (sum >= 0x10000)//����ԭ��У���һ��������
		{
			int s = sum >> 16;
			sum -= 0x10000;
			sum += s;
		}
	}
	if (sum == 65535)//Դ��+����-��ȫ1
		return 1;//У�����ȷ
	return 0;
}
