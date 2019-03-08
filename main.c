//===----------------------------------------------------------------------===//
//
//                  PPF - Process packet filtering machine
//
//===----------------------------------------------------------------------===//
//
//  main.c - 03/05/2019
//
//  Copyright (C) 2019. rollrat. All Rights Reserved.
//
//===----------------------------------------------------------------------===//

#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <signal.h>
#include <string.h>
#include <stdint.h>
#include <ws2tcpip.h>
#include <Iphlpapi.h>
#include <TlHelp32.h>
#include <windivert.h>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")

#define MAX_PACKET_SIZE 32768

#define FILTERING_BY_PROCESSNAME 1
#define PROCESS_NAME "chrome.exe"

static char *format_ipaddress(uint32_t ipaddr)
{
  static char str[16];
  char *ptr = str;
  while (ipaddr) {
    char tmp[5];
    _itoa(ipaddr >> 24, tmp, 10);
    ptr = strcpy(ptr, tmp) + strlen(tmp);
    *ptr = '.';
    ptr++;
    ipaddr <<= 8;
  }
  *--ptr = 0;
  return str;
}

static DWORD find_processid_by_port(u_short src_port, u_short dst_port)
{
  MIB_TCPTABLE_OWNER_PID *pTCPInfo;
  MIB_TCPROW_OWNER_PID *owner;
  DWORD size;
  DWORD dwResult;

  dwResult = GetExtendedTcpTable(NULL, &size, 0, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
  pTCPInfo = (MIB_TCPTABLE_OWNER_PID*)malloc(size);
  dwResult = GetExtendedTcpTable(pTCPInfo, &size, 0, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);

  //
  //  Enumerate ports info.
  //
  for (DWORD dwLoop = 0; dwLoop < pTCPInfo->dwNumEntries; dwLoop++)
  {
    owner = &pTCPInfo->table[dwLoop];
    int open = ntohs(owner->dwLocalPort);
    int remote = ntohs(owner->dwRemotePort);

    if (open == src_port && remote == dst_port)
      return owner->dwOwningPid;
  }
  return -1;
}

static char *find_processname_by_pid(DWORD pid)
{
  //
  //  Enumerate process info.
  //
  HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (hSnapshot) {
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hSnapshot, &pe32)) {
      do {
        if (pe32.th32ProcessID == pid) {
          return _strdup(pe32.szExeFile);
        }
      } while (Process32Next(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);
  }
  return "null";
}

static void print_packet_info(PWINDIVERT_IPHDR ppIpHdr, PWINDIVERT_IPV6HDR ppIpV6Hdr, PWINDIVERT_TCPHDR ppTcpHdr)
{
  DWORD pid = find_processid_by_port(ntohs(ppTcpHdr->SrcPort), ntohs(ppTcpHdr->DstPort));

  printf("=============================================\n");

  printf("process: %d (%s)\n", pid, find_processname_by_pid(pid));

  printf("src-port: %d, ", ntohs(ppTcpHdr->SrcPort));
  printf("dest-port: %d\n", ntohs(ppTcpHdr->DstPort));

  if (ppIpHdr != NULL)
  {
    printf("src: %s, ", format_ipaddress(ppIpHdr->SrcAddr));
    printf("dest: %s\n", format_ipaddress(ppIpHdr->DstAddr));
  }
  else
  {
    printf("src: %s, ", format_ipaddress(ppIpV6Hdr->SrcAddr));
    printf("dest: %s\n", format_ipaddress(ppIpV6Hdr->DstAddr));
  }
}

int main()
{
  char *filter = "tcp";
  HANDLE w_filter;
  WINDIVERT_ADDRESS addr;
  char packet[MAX_PACKET_SIZE];
  PVOID packet_data;
  UINT packetLen;
  UINT packet_dataLen;
  PWINDIVERT_IPHDR ppIpHdr;
  PWINDIVERT_IPV6HDR ppIpV6Hdr;
  PWINDIVERT_TCPHDR ppTcpHdr;
  int ports[65535] = { 0, };

  w_filter = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, 0, 0);

  while (1) {
    if (WinDivertRecv(w_filter, packet, sizeof(packet), &addr, &packetLen)) {

      if (WinDivertHelperParsePacket(packet, packetLen, &ppIpHdr,
        NULL, NULL, NULL, &ppTcpHdr, NULL, &packet_data, &packet_dataLen))
        ;
      else if (WinDivertHelperParsePacket(packet, packetLen, NULL,
        &ppIpV6Hdr, NULL, NULL, &ppTcpHdr, NULL, &packet_data, &packet_dataLen))
        ;
      else if (WinDivertHelperParsePacket(packet, packetLen, &ppIpHdr,
        NULL, NULL, NULL, &ppTcpHdr, NULL, NULL, NULL))
        ;
      else if (WinDivertHelperParsePacket(packet, packetLen, NULL,
        &ppIpV6Hdr, NULL, NULL, &ppTcpHdr, NULL, NULL, NULL))
        ;

      // Filter UDP packets;
      if (ppTcpHdr == NULL)
        continue;

#if FILTERING_BY_PROCESSNAME
      if (!strcmp(PROCESS_NAME, find_processname_by_pid(
        find_processid_by_port(ntohs(ppTcpHdr->SrcPort), ntohs(ppTcpHdr->DstPort))))) {

        ports[ntohs(ppTcpHdr->SrcPort)]++;

        print_packet_info(ppIpHdr, ppIpV6Hdr, ppTcpHdr);
        for (int i = 0; i < 65535; i++)
          if (ports[i] > 0)
            printf(" -- %d (%d)\n", i, ports[i]);
      }
#else
      print_packet_info(ppIpHdr, ppIpV6Hdr, ppTcpHdr);
#endif

      WinDivertSend(w_filter, packet, packetLen, &addr, NULL);
    }
  }
}