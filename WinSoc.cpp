#include <SDKDDKVer.h>
#define WIN32_LEAN_AND_MEAN
#define NOIME
#define NOSERVICE
#include <stdio.h>
#include <windows.h>
#include <WinSock2.h>
#include <mswsock.h>
#include <MSTcpIP.h>
#include <process.h>
#pragma comment(lib, "WS2_32.lib")
#pragma comment(lib, "msvcrt.lib")

#define tcp_server_connt 1 // TCP 服务器连接状态
#define tcp_server_recv 2  // TCP 服务器接收数据状态
#define tcp_server_stop 3  // TCP 服务器停止状态
#define tcp_server_send 4  // TCP 服务器发送数据状态
#define tcp_server_close 5 // TCP 服务器关闭状态

#define tcp_client_connt 1 // TCP 客户端连接状态
#define tcp_client_recv 2  // TCP 客户端接收数据状态
#define tcp_client_stop 3  // TCP 客户端停止状态
#define tcp_client_send 4  // TCP 客户端发送数据状态
#define tcp_client_close 5 // TCP 客户端关闭状态
int worker = 0;
int cache = 512;
HANDLE hEvent_Server = NULL; // 初始化服务器事件句柄为 NULL
HANDLE hEvent_Client = NULL; // 初始化客户端事件句柄为 NULL

typedef void(__stdcall *onServer_ex)(HANDLE Server, SOCKET hSocket, int type, char *data, int size);
typedef void(__stdcall *onClient_ex)(HANDLE Client, SOCKET hSocket, int type, char *data, int size);

extern onServer_ex onServerFunc; // 全局变量，服务器事件回调函数指针
extern onClient_ex onClientFunc; // 全局变量，客户端事件回调函数指针

int closesockets(SOCKET hSocket)
{
	int code = 0;
	// 检查套接字是否有效，如果无效则直接返回
	if (hSocket == INVALID_SOCKET)
	{
		return code; // 返回 0 表示未执行任何操作
	}

	// 设置 SO_LINGER 选项，确保立即关闭连接
	struct linger pLinger;
	pLinger.l_onoff = 1;  // 启用 SO_LINGER 选项
	pLinger.l_linger = 0; // 延迟时间为 0，立即关闭连接

	// 设置套接字选项
	code = setsockopt(hSocket, SOL_SOCKET, SO_LINGER, (char *)&pLinger, sizeof(pLinger));
	if (code == SOCKET_ERROR)
	{
		// 处理 setsockopt 错误，例如记录日志或返回特定错误码
		return code;
	}

	// 关闭套接字的发送和接收功能
	code = shutdown(hSocket, SD_BOTH);
	if (code == SOCKET_ERROR)
	{
		// 处理 shutdown 错误，例如记录日志或返回特定错误码
		return code;
	}

	// 关闭套接字并返回关闭结果
	return closesocket(hSocket); // 返回 closesocket 函数的返回值，表示关闭套接字的状态
}

class SERVER;
typedef struct SERVER_ST
{
	OVERLAPPED Socket_ST; // OVERLAPPED 结构用于异步 I/O
	SERVER *instance;	  // 指向服务器对象的指针
	int state;			  // 服务器连接的状态
	SOCKET hSocket;		  // 客户端套接字
	char *data;			  // 数据缓冲区
	DWORD bytes;		  // 传输的字节数
	DWORD size;			  // 缓冲区大小
	DWORD offset;		  // 缓冲区的偏移量
} PX_SERVER, *PS_SERVER;  // 定义结构体指针类型

class SERVER
{
public:
	SERVER(void);
	~SERVER(void);
	int alloc(char *host, unsigned short port, bool mete);
	int Accept();
	void OnAccept(bool state, PS_SERVER PS);
	void OnRecv(bool state, PS_SERVER PS);
	void OnClose(bool state, PS_SERVER PS);
	void OnSend(bool state, PS_SERVER op);
	int close();

public:
	SOCKET m_hSocket;
	BOOL m_mate;
	BOOL m_stop;
};

SERVER::SERVER(void)
{
	m_hSocket = INVALID_SOCKET;
}

SERVER::~SERVER(void)
{
	m_hSocket = INVALID_SOCKET;
}
int SERVER::alloc(char *host, unsigned short port, bool mete)
{
	m_mate = mete;
	m_hSocket = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, 0, 0, WSA_FLAG_OVERLAPPED);
	if (INVALID_SOCKET == m_hSocket)
	{
		return WSAGetLastError(); // 返回错误码
	}
	if (CreateIoCompletionPort((HANDLE)m_hSocket, hEvent_Server, 0, 0) == NULL)
	{
		close();			   // 关闭套接字
		return GetLastError(); // 返回错误码
	}
	// 设置套接字地址信息
	sockaddr_in pSockaddr;
	pSockaddr.sin_family = AF_INET;
	pSockaddr.sin_addr.s_addr = inet_addr(host);
	pSockaddr.sin_port = htons(port);
	if (bind(m_hSocket, (SOCKADDR *)&pSockaddr, sizeof(pSockaddr)) == SOCKET_ERROR)
	{
		close();				  // 关闭套接字
		return WSAGetLastError(); // 返回错误码
	}
	// 开始监听连接
	if (listen(m_hSocket, worker) == SOCKET_ERROR)
	{
		close();				  // 关闭套接字
		return WSAGetLastError(); // 返回错误码
	}
	SERVER_ST *Socket_ST = new SERVER_ST;
	memset(Socket_ST, 0, sizeof(SERVER_ST));
	Socket_ST->instance = this;
	Socket_ST->state = tcp_server_connt;

	Socket_ST->data = new char[cache];
	Socket_ST->size = cache;
	Socket_ST->offset = 0;
	Socket_ST->hSocket = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, 0, 0, WSA_FLAG_OVERLAPPED);
	if (Socket_ST->hSocket == INVALID_SOCKET)
	{
		delete[] Socket_ST->data;
		Socket_ST->data = NULL;
		delete Socket_ST;
		Socket_ST = NULL;
		close();				  // 关闭套接字
		return WSAGetLastError(); // 返回错误码
	}
	setsockopt(Socket_ST->hSocket, SOL_SOCKET, SO_RCVBUF, (const char *)&cache, sizeof(int));
	setsockopt(Socket_ST->hSocket, SOL_SOCKET, SO_SNDBUF, (const char *)&cache, sizeof(int));
	BOOL reuse = TRUE;
	setsockopt(Socket_ST->hSocket, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse, sizeof(BOOL));
	if (CreateIoCompletionPort((HANDLE)Socket_ST->hSocket, hEvent_Server, 0, 0) == NULL)
	{
		closesocket(Socket_ST->hSocket);
		Socket_ST->hSocket = INVALID_SOCKET;
		delete[] Socket_ST->data;
		Socket_ST->data = NULL;
		delete Socket_ST;
		Socket_ST = NULL;
		close();
		return GetLastError();
	}

	LPFN_ACCEPTEX lpfnAcceptEx = NULL;
	GUID lGUID = WSAID_ACCEPTEX;
	DWORD bytes = 0;
	if (WSAIoctl(m_hSocket, SIO_GET_EXTENSION_FUNCTION_POINTER, &lGUID, sizeof(GUID), &lpfnAcceptEx, sizeof(lpfnAcceptEx), &bytes, NULL, NULL))
	{
		closesocket(Socket_ST->hSocket);
		Socket_ST->hSocket = INVALID_SOCKET;
		delete[] Socket_ST->data;
		Socket_ST->data = NULL;
		delete Socket_ST;
		Socket_ST = NULL;
		close();  // 关闭套接字
		return 2; // 返回错误码
	}
	DWORD bytesReturned = 0;
	if (lpfnAcceptEx(m_hSocket, Socket_ST->hSocket, Socket_ST->data, 0, sizeof(sockaddr) + 16, sizeof(sockaddr) + 16, &bytesReturned, (LPOVERLAPPED)Socket_ST))
	{
		closesocket(Socket_ST->hSocket);
		Socket_ST->hSocket = INVALID_SOCKET;
		delete[] Socket_ST->data;
		Socket_ST->data = NULL;
		delete Socket_ST;
		Socket_ST = NULL;
		close();  // 关闭套接字
		return 3; // 返回错误码
	}
	return 0;
}
int SERVER::Accept()
{

	SERVER_ST *Socket_ST = new SERVER_ST;
	memset(Socket_ST, 0, sizeof(SERVER_ST));
	Socket_ST->instance = this;
	Socket_ST->state = tcp_server_connt;

	Socket_ST->data = new char[cache];
	Socket_ST->size = cache;
	Socket_ST->offset = 0;

	Socket_ST->hSocket = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, 0, 0, WSA_FLAG_OVERLAPPED);
	if (Socket_ST->hSocket == INVALID_SOCKET)
	{
		delete[] Socket_ST->data;
		Socket_ST->data = NULL;
		delete Socket_ST;
		Socket_ST = NULL;
		return WSAGetLastError();
	}
	setsockopt(Socket_ST->hSocket, SOL_SOCKET, SO_RCVBUF, (const char *)&cache, sizeof(int));
	setsockopt(Socket_ST->hSocket, SOL_SOCKET, SO_SNDBUF, (const char *)&cache, sizeof(int));
	BOOL reuse = TRUE;
	setsockopt(Socket_ST->hSocket, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse, sizeof(BOOL));
	if (CreateIoCompletionPort((HANDLE)Socket_ST->hSocket, hEvent_Server, 0, 0) == NULL)
	{
		closesocket(Socket_ST->hSocket);
		Socket_ST->hSocket = INVALID_SOCKET;

		PostQueuedCompletionStatus(hEvent_Server, 0, 0, (LPOVERLAPPED)Socket_ST);

		delete[] Socket_ST->data;
		Socket_ST->data = NULL;
		delete Socket_ST;
		Socket_ST = NULL;
		return GetLastError();
	}
	LPFN_ACCEPTEX lpfnAcceptEx = NULL;
	GUID guidAcceptEx = WSAID_ACCEPTEX;
	DWORD bytesReturned = 0;
	if (WSAIoctl(m_hSocket, SIO_GET_EXTENSION_FUNCTION_POINTER, &guidAcceptEx, sizeof(GUID), &lpfnAcceptEx, sizeof(lpfnAcceptEx), &bytesReturned, NULL, NULL))
	{
		// 如果获取函数指针失败，关闭套接字，释放资源，并返回错误码
		closesocket(Socket_ST->hSocket);
		Socket_ST->hSocket = INVALID_SOCKET;

		PostQueuedCompletionStatus(hEvent_Server, 0, 0, (LPOVERLAPPED)Socket_ST);

		delete[] Socket_ST->data;
		Socket_ST->data = NULL;
		delete Socket_ST;
		Socket_ST = NULL;
		return 2;
	}

	DWORD bytesTransferred = 0;
	if (lpfnAcceptEx(m_hSocket, Socket_ST->hSocket, Socket_ST->data, 0, sizeof(sockaddr) + 16, sizeof(sockaddr) + 16, &bytesTransferred, (LPOVERLAPPED)Socket_ST))
	{
		// 如果AcceptEx调用失败，关闭套接字，释放资源，并返回错误码
		closesocket(Socket_ST->hSocket);
		Socket_ST->hSocket = INVALID_SOCKET;

		PostQueuedCompletionStatus(hEvent_Server, 0, 0, (LPOVERLAPPED)Socket_ST);

		delete[] Socket_ST->data;
		Socket_ST->data = NULL;
		delete Socket_ST;
		Socket_ST = NULL;
		return 3;
	}

	return 0;
}

void SERVER::OnAccept(bool stop, PS_SERVER PS)
{
	while (Accept() != 0)
	{
		Sleep(1);
	}
	setsockopt(PS->hSocket, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, (char *)&m_hSocket, sizeof(SOCKET));

	tcp_keepalive keepAliveParams;
	keepAliveParams.onoff = 1;
	keepAliveParams.keepalivetime = 1000 * 30;	  // 30秒
	keepAliveParams.keepaliveinterval = 1000 * 5; // 5秒
	DWORD bytesReturned = 0;
	WSAIoctl(PS->hSocket, SIO_KEEPALIVE_VALS, &keepAliveParams, sizeof(keepAliveParams), NULL, 0, &bytesReturned, NULL, NULL);
	onServerFunc(this, PS->hSocket, tcp_server_connt, NULL, 0);
	if (stop != true)
	{
		PS->state = tcp_server_recv;
		WSABUF wsabuf;
		if (m_mate)
		{
			delete[] PS->data;
			PS->data = new char[sizeof(DWORD)];
			PS->size = sizeof(DWORD);
			PS->offset = 0;

			wsabuf.buf = PS->data + PS->offset;
			wsabuf.len = PS->size - PS->offset;
		}
		else
		{
			wsabuf.buf = PS->data;
			wsabuf.len = cache;
		}

		DWORD flags = 0;
		bytesReturned = 0;
		if (WSARecv(PS->hSocket, &wsabuf, 1, &bytesReturned, &flags, (LPWSAOVERLAPPED)PS, NULL))
		{
			int code = WSAGetLastError();
			if (code == WSAEFAULT)
			{
				return;
			}
			else if (code != WSA_IO_PENDING)
			{
				// 如果不是WSA_IO_PENDING，关闭套接字并清理PS
				onServerFunc(this, PS->hSocket, tcp_server_close, NULL, 0);
				closesocket(PS->hSocket);
				PS->hSocket = INVALID_SOCKET;
				delete[] PS->data;
				PS->data = NULL;
				delete PS;
				PS = NULL;
			}
		}
	}
	else
	{
		onServerFunc(this, PS->hSocket, tcp_server_close, NULL, 0);
		closesocket(PS->hSocket);
		PS->hSocket = INVALID_SOCKET;
		delete[] PS->data;
		PS->data = NULL;
		delete PS;
		PS = NULL;
	}
}
void SERVER::OnRecv(bool stop, PS_SERVER PS)
{
	if (stop != true)
	{
		if (m_mate)
		{
			PS->offset += PS->bytes;
			if (PS->offset < PS->size)
			{
				// 数据未接收完整，继续接收
				PS->state = tcp_server_recv;
				WSABUF wsabuf;
				wsabuf.buf = PS->data + PS->offset;
				wsabuf.len = PS->size - PS->offset;
				DWORD dwRecvByte = 0;
				DWORD Flags = 0;
				if (WSARecv(PS->hSocket, &wsabuf, 1, &dwRecvByte, &Flags, (LPWSAOVERLAPPED)PS, NULL))
				{
					int ercode = WSAGetLastError();
					if (ercode == WSAEFAULT)
					{
						return;
					}
					else if (ercode != WSA_IO_PENDING)
					{
						// 如果接收出错，关闭服务器并释放资源
						onServerFunc(this, PS->hSocket, tcp_server_close, 0, 0);
						delete[] PS->data;
						PS->data = NULL;
						delete PS;
						PS = NULL;
						return;
					}
				}
			}
			// 取出包头字节长度
			DWORD size = *((DWORD *)(PS->data));
			if (size > 65536000)
			{
				// 数据大小超出限制，关闭服务器并释放资源
				onServerFunc(this, PS->hSocket, tcp_server_close, 0, 0);
				delete[] PS->data;
				PS->data = NULL;
				delete PS;
				PS = NULL;
				return;
			}
			// 判断偏移大小是否大于数据大小 offset < (Size + data)  代表数据接收完成
			if (PS->offset < DWORD(sizeof(DWORD)) + size)
			{
				onServerFunc(this, PS->hSocket, tcp_server_recv, PS->data + sizeof(DWORD), PS->size - sizeof(DWORD));
			}
			delete[] PS->data;
			PS->data = new char[sizeof(DWORD)];
			PS->size = sizeof(DWORD);
		}
		else
		{
			onServerFunc(this, PS->hSocket, tcp_server_recv, PS->data, PS->bytes);
		}

		// 重置接收状态与数据偏移
		PS->offset = 0;
		PS->state = tcp_server_recv;

		WSABUF wsabuf;
		if (m_mate)
		{
			wsabuf.buf = PS->data + PS->offset;
			wsabuf.len = PS->size - PS->offset;
		}
		else
		{
			wsabuf.buf = PS->data;
			wsabuf.len = cache;
		}
		DWORD dwBufferCount = 1;
		DWORD dwRecvBytes = 0;
		DWORD Flags = 0;
		if (WSARecv(PS->hSocket, &wsabuf, dwBufferCount, &dwRecvBytes, &Flags, (LPWSAOVERLAPPED)PS, NULL))
		{
			int ercode = WSAGetLastError();
			if (ercode == WSAEFAULT)
			{
				return;
			}
			else if (ercode != WSA_IO_PENDING)
			{
				// 如果接收出错，关闭服务器并释放资源
				onServerFunc(this, PS->hSocket, tcp_server_close, 0, 0);
				delete[] PS->data;
				PS->data = NULL;
				delete PS;
				PS = NULL;
			}
		}

	}
	else
	{
		// 如果出现错误，执行关闭服务器函数，并释放资源
		onServerFunc(this, PS->hSocket, tcp_server_close, 0, 0);
		delete[] PS->data;
		PS->data = NULL;
		delete PS;
		PS = NULL;
	}
}

int SERVER::close()
{
	m_stop = TRUE;
	closesockets(m_hSocket);
	m_hSocket = INVALID_SOCKET;
	return 0;
}
class CLIENT;
typedef struct CLIENT_ST
{
	OVERLAPPED Socket_ST; // 用于重叠I/O操作的结构
	CLIENT *instance;	  // 指向CLIENT实例的指针
	int state;			  // 客户端连接的状态
	char *data;			  // 数据缓冲区
	DWORD bytes;		  // 传输的字节数
	DWORD size;			  // 缓冲区的大小
	DWORD offset;		  // 缓冲区的偏移量
} PX_CLIENT, *PS_CLIENT;  // 结构体及其指针的类型定义
class CLIENT
{
public:
	CLIENT(void);
	~CLIENT(void);
	int alloc(char *host, unsigned short port, bool mete, int time);
	void OnConnect(bool state, PS_CLIENT PS);
	void OnRecv(bool state, PS_CLIENT PS);
	void OnClose(bool state, PS_CLIENT PS);
	int close();

public:
	SOCKET m_hSocket;
	BOOL m_mate;
};
CLIENT::CLIENT(void)
{
	m_hSocket = INVALID_SOCKET;
}
CLIENT::~CLIENT(void)
{
	m_hSocket = INVALID_SOCKET;
}
int CLIENT::alloc(char *host, unsigned short port, bool mete, int time)
{
	return 0;
}
int CLIENT::close()
{
	return 0;
}
int main(int argc, char const *argv[])
{
	// printf("%s\n", "WinSock2");

	return 0;
}