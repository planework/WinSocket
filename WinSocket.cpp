#include <SDKDDKVer.h>
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <WinSock2.h>
#include <string.h>
#pragma comment(lib, "WS2_32.lib")
#pragma comment(lib, "msvcrt.lib")
#include <stdio.h>
#include <mswsock.h>
#include <MSTcpIP.h>
#include <process.h>
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

#define pack 65535 // TCP 消息最大长度

typedef void(__stdcall *onServer_ex)(HANDLE Server, SOCKET hSocket, int type, char *data, int len);
typedef void(__stdcall *onClient_ex)(HANDLE Client, SOCKET hSocket, int type, char *data, int len);
extern int worker; // 全局变量，CPU 数量
extern int cache;  // 全局变量，缓冲区长度

extern HANDLE hEvent_Server; // 全局变量，服务器事件句柄
extern HANDLE hEvent_Client; // 全局变量，客户端事件句柄

extern onServer_ex onServerFunc; // 全局变量，服务器事件回调函数指针
extern onClient_ex onClientFunc; // 全局变量，客户端事件回调函数指针

HANDLE hEvent_Server = NULL;	 // 初始化服务器事件句柄为 NULL
HANDLE hEvent_Client = NULL;	 // 初始化客户端事件句柄为 NULL
int worker = 0;					 // 初始化 CPU 数量为 0
int cache = 512;				 // 初始化缓冲区长度为 512 字节
onServer_ex onServerFunc = NULL; // 初始化服务器事件回调函数指针为 NULL
onClient_ex onClientFunc = NULL; // 初始化客户端事件回调函数指针为 NULL

// 关闭套接字函数
int closesockets(SOCKET hSocket)
{
	// 检查套接字是否有效，如果无效则直接返回
	if (hSocket == INVALID_SOCKET)
	{
		return 0; // 返回 0 表示未执行任何操作
	}

	// 设置 SO_LINGER 选项，确保立即关闭连接
	struct linger lingerStruct;
	lingerStruct.l_onoff = 1;  // 启用 SO_LINGER 选项
	lingerStruct.l_linger = 0; // 延迟时间为 0，立即关闭连接

	// 设置套接字选项
	int result = setsockopt(hSocket, SOL_SOCKET, SO_LINGER, (char *)&lingerStruct, sizeof(lingerStruct));
	if (result == SOCKET_ERROR)
	{
		// 处理 setsockopt 错误，例如记录日志或返回特定错误码
		return SOCKET_ERROR;
	}

	// 关闭套接字的发送和接收功能
	result = shutdown(hSocket, SD_BOTH);
	if (result == SOCKET_ERROR)
	{
		// 处理 shutdown 错误，例如记录日志或返回特定错误码
		return SOCKET_ERROR;
	}

	// 关闭套接字并返回关闭结果
	return closesocket(hSocket); // 返回 closesocket 函数的返回值，表示关闭套接字的状态
}

class SERVER;
// 定义一个结构体用于存储服务器信息
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
	// 构造函数，初始化成员变量
	SERVER(void);
	// 析构函数，清理资源
	~SERVER(void);

public:
	// 初始化服务器，设置监听的主机和端口
	int Init(char *host, unsigned short nPort, int mete);
	// 接受一个客户端连接
	int Accept();
	// 处理客户端连接完成事件
	void OnAccept(bool error, PS_SERVER Socket_ST);
	// 处理数据接收事件
	void OnRecv(bool error, PS_SERVER Socket_ST);
	// 关闭服务器
	int Close();
	// 异步发送数据
	int doSend(SOCKET hSocket, char *data, DWORD size);
	// 同步发送数据
	int doSend_sync(SOCKET hSocket, char *data, DWORD size);
	// 处理发送完成事件
	void OnSend(bool ercode, PS_SERVER Socket_ST);
	// 获取远程客户端的 IP 地址
	char *get_ip(SOCKET hSocket)
	{
		sockaddr_in pSockaddr;
		int size = sizeof(pSockaddr);
		getpeername(hSocket, (sockaddr *)&pSockaddr, &size);
		return inet_ntoa(pSockaddr.sin_addr);
	}
	// 获取服务器的套接字
	SOCKET get_socket()
	{
		return m_hSocket;
	}
	// 获取服务器监听的端口号
	u_short get_port()
	{
		sockaddr_in pSockaddr;
		int size = sizeof(pSockaddr);
		getsockname(m_hSocket, (sockaddr *)&pSockaddr, &size);
		return ntohs(pSockaddr.sin_port);
	}
	// 获取服务器监听的地址
	char *get_addr(SOCKET m_hSocket)
	{
		sockaddr_in pSockaddr;
		int size = sizeof(pSockaddr);
		getsockname(m_hSocket, (sockaddr *)&pSockaddr, &size);
		return inet_ntoa(pSockaddr.sin_addr);
	}

public:
	SOCKET m_hSocket; // 服务器套接字
	BOOL m_mate;	  // 是否特殊条件
	BOOL m_stop;	  // 是否停止
};

// 构造函数，初始化成员变量
SERVER::SERVER(void)
{
	m_stop = FALSE;				// 初始化停止标志为 FALSE
	m_hSocket = INVALID_SOCKET; // 初始化套接字为无效值
}

// 析构函数，清理资源
SERVER::~SERVER(void)
{
	m_hSocket = INVALID_SOCKET; // 重置套接字为无效值
}

// 初始化服务器
int SERVER::Init(char *host, unsigned short port, int mete)
{
	m_mate = mete; // 设置元数据

	// 创建监听套接字
	m_hSocket = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, 0, 0, WSA_FLAG_OVERLAPPED);
	if (INVALID_SOCKET == m_hSocket)
	{
		return WSAGetLastError(); // 返回错误码
	}

	// 将套接字关联到完成端口上

	if (CreateIoCompletionPort((HANDLE)m_hSocket, hEvent_Server, 0, 0) == NULL)
	{
		Close();			   // 关闭套接字
		return GetLastError(); // 返回错误码
	}

	// 设置套接字地址信息
	sockaddr_in pSockaddr;
	pSockaddr.sin_family = AF_INET;
	pSockaddr.sin_addr.s_addr = inet_addr(host);
	pSockaddr.sin_port = htons(port);

	// 绑定套接字
	if (bind(m_hSocket, (SOCKADDR *)&pSockaddr, sizeof(pSockaddr)) == SOCKET_ERROR)
	{
		Close();				  // 关闭套接字
		return WSAGetLastError(); // 返回错误码
	}

	// 开始监听连接
	if (listen(m_hSocket, worker) == SOCKET_ERROR)
	{
		Close();				  // 关闭套接字
		return WSAGetLastError(); // 返回错误码
	}

	// 创建服务器状态结构体并初始化
	SERVER_ST *Socket_ST = new SERVER_ST;
	memset(Socket_ST, 0, sizeof(SERVER_ST));
	Socket_ST->data = new char[cache];
	Socket_ST->instance = this;
	Socket_ST->size = cache;
	Socket_ST->offset = 0;
	Socket_ST->state = tcp_server_connt;
	Socket_ST->hSocket = INVALID_SOCKET;
	Socket_ST->hSocket = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, 0, 0, WSA_FLAG_OVERLAPPED);

	// 检查服务器状态结构体的套接字
	if (Socket_ST->hSocket == INVALID_SOCKET)
	{
		delete[] Socket_ST->data;
		Socket_ST->data = NULL;
		delete Socket_ST;
		Socket_ST = NULL;
		Close();				  // 关闭套接字
		return WSAGetLastError(); // 返回错误码
	}

	// 设置接收缓冲区大小
	setsockopt(Socket_ST->hSocket, SOL_SOCKET, SO_RCVBUF, (const char *)&cache, sizeof(int));
	int nSendBuf = 0;
	// 设置发送缓冲区大小
	setsockopt(Socket_ST->hSocket, SOL_SOCKET, SO_SNDBUF, (const char *)&nSendBuf, sizeof(int));
	BOOL bReuseaddr = TRUE;
	// 设置地址重用
	setsockopt(Socket_ST->hSocket, SOL_SOCKET, SO_REUSEADDR, (const char *)&bReuseaddr, sizeof(BOOL));

	// 将套接字关联到完成端口上
	if (CreateIoCompletionPort((HANDLE)Socket_ST->hSocket, hEvent_Server, 0, 0) == NULL)
	{
		closesocket(Socket_ST->hSocket);
		Socket_ST->hSocket = INVALID_SOCKET;
		delete[] Socket_ST->data;
		Socket_ST->data = NULL;
		delete Socket_ST;
		Socket_ST = NULL;
		Close();			   // 关闭套接字
		return GetLastError(); // 返回错误码
	}

	// 获取AcceptEx函数指针
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
		Close();  // 关闭套接字
		return 2; // 返回错误码
	}

	DWORD bytesReturned = 0;
	// 调用AcceptEx函数
	if (lpfnAcceptEx(m_hSocket, Socket_ST->hSocket, Socket_ST->data, 0, sizeof(sockaddr) + 16, sizeof(sockaddr) + 16, &bytesReturned, (LPOVERLAPPED)Socket_ST))
	{
		closesocket(Socket_ST->hSocket);
		Socket_ST->hSocket = INVALID_SOCKET;
		delete[] Socket_ST->data;
		Socket_ST->data = NULL;
		delete Socket_ST;
		Socket_ST = NULL;
		Close();  // 关闭套接字
		return 3; // 返回错误码
	}

	return 0; // 初始化成功
}

int SERVER::Close()
{
	// 设置服务器停止标志为TRUE，表示服务器即将停止运行
	m_stop = TRUE;

	// 关闭服务器套接字，释放相关资源
	closesockets(m_hSocket);

	// 将套接字句柄设置为无效
	m_hSocket = INVALID_SOCKET;

	// 返回0表示成功关闭服务器
	return 0;
}

int SERVER::Accept()
{
	// 创建一个套接字状态结构体对象，并进行初始化
	SERVER_ST *Socket_ST = new SERVER_ST;
	memset(Socket_ST, 0, sizeof(SERVER_ST));

	// 分配缓冲区
	Socket_ST->data = new char[cache];
	Socket_ST->instance = this;
	Socket_ST->size = cache;
	Socket_ST->offset = 0;
	Socket_ST->state = tcp_server_connt;

	// 创建一个套接字
	Socket_ST->hSocket = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, 0, 0, WSA_FLAG_OVERLAPPED);

	// 检查套接字是否创建成功
	if (INVALID_SOCKET == Socket_ST->hSocket)
	{
		// 如果创建失败，释放资源并返回错误码
		delete[] Socket_ST->data;
		Socket_ST->data = NULL;
		delete Socket_ST;
		Socket_ST = NULL;
		return WSAGetLastError();
	}

	// 设置接收缓冲区大小
	setsockopt(Socket_ST->hSocket, SOL_SOCKET, SO_RCVBUF, (const char *)&cache, sizeof(int));

	// 设置发送缓冲区大小为0
	int sendBufferSize = 0;
	setsockopt(Socket_ST->hSocket, SOL_SOCKET, SO_SNDBUF, (const char *)&sendBufferSize, sizeof(int));

	// 设置SO_REUSEADDR选项
	BOOL reuseAddr = TRUE;
	setsockopt(Socket_ST->hSocket, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuseAddr, sizeof(BOOL));

	// 将套接字关联到完成端口上
	HANDLE completionPortHandle = NULL;
	completionPortHandle = CreateIoCompletionPort((HANDLE)Socket_ST->hSocket, hEvent_Server, 0, 0);

	// 检查关联完成端口是否成功
	if (NULL == completionPortHandle)
	{
		// 如果关联失败，关闭套接字，释放资源，并返回错误码
		closesocket(Socket_ST->hSocket);
		Socket_ST->hSocket = INVALID_SOCKET;
		PostQueuedCompletionStatus(hEvent_Server, 0, 0, (LPOVERLAPPED)Socket_ST);
		delete[] Socket_ST->data;
		Socket_ST->data = NULL;
		delete Socket_ST;
		Socket_ST = NULL;
		return GetLastError();
	}

	// 获取AcceptEx函数指针
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

	// 调用AcceptEx函数
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

	// 返回0表示接受操作成功
	return 0;
}

void SERVER::OnAccept(bool error, PS_SERVER PS)
{
	// 循环接受连接，直到接受完成
	while (0 != Accept())
	{
		Sleep(1);
	}

	// 设置套接字选项
	setsockopt(PS->hSocket, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, (char *)&m_hSocket, sizeof(SOCKET));

	// 设置TCP keep-alive参数

	tcp_keepalive keepAliveParams;
	keepAliveParams.onoff = 1;
	keepAliveParams.keepalivetime = 1000 * 30;	  // 30秒
	keepAliveParams.keepaliveinterval = 1000 * 5; // 5秒
	DWORD bytesReturned = 0;
	WSAIoctl(PS->hSocket, SIO_KEEPALIVE_VALS, &keepAliveParams, sizeof(keepAliveParams), NULL, 0, &bytesReturned, NULL, NULL);

	// 调用服务器功能回调函数
	onServerFunc(this, PS->hSocket, tcp_server_connt, NULL, 0);

	// 如果有错误，处理并关闭套接字
	if (error)
	{
		onServerFunc(this, PS->hSocket, tcp_server_close, NULL, 0);
		closesocket(PS->hSocket);
		PS->hSocket = INVALID_SOCKET;
		delete[] PS->data;
		PS->data = NULL;
		delete PS;
		PS = NULL;
		return;
	}

	// 设置PS的状态为接收数据
	PS->state = tcp_server_recv;

	WSABUF wsabuf;
	if (m_mate)
	{
		// 释放之前的数据，为新数据分配空间
		delete[] PS->data;
		PS->offset = 0;
		PS->data = new char[sizeof(DWORD)];
		PS->size = sizeof(DWORD);
		wsabuf.buf = PS->data + PS->offset;
		wsabuf.len = PS->size - PS->offset;
	}
	else
	{
		// 直接使用PS的数据缓冲区
		wsabuf.buf = PS->data;
		wsabuf.len = cache;
	}

	DWORD flags = 0;
	bytesReturned = 0;

	// 异步接收数据
	if (WSARecv(PS->hSocket, &wsabuf, 1, &bytesReturned, &flags, (LPWSAOVERLAPPED)PS, NULL))
	{
		int code = WSAGetLastError();

		// 如果错误码是WSAEFAULT，直接返回
		if (code == WSAEFAULT)
		{
			return;
		}
		// 如果不是WSA_IO_PENDING，关闭套接字并清理PS
		else if (code != WSA_IO_PENDING)
		{
			onServerFunc(this, PS->hSocket, tcp_server_close, NULL, 0);
			closesocket(PS->hSocket);
			PS->hSocket = INVALID_SOCKET;
			delete[] PS->data;
			PS->data = NULL;
			delete PS;
			PS = NULL;
			return;
		}
	}
}
void SERVER::OnRecv(bool error, PS_SERVER PS)
{
    if (error)
    {
        // If there's an error, close the server and release resources
        onServerFunc(this, PS->hSocket, tcp_server_close, 0, 0);
        delete[] PS->data;
        delete PS;
        PS = NULL;
        return;
    }

    PS->offset += PS->bytes;

    if (m_mate)
    {
        if (PS->offset < PS->size)
        {
            // Data not fully received, continue receiving
            PS->state = tcp_server_recv;
            WSABUF wsabuf;
            wsabuf.buf = PS->data + PS->offset;
            wsabuf.len = PS->size - PS->offset;
            DWORD dwRecvByte = 0;
            DWORD Flags = 0;
            if (WSARecv(PS->hSocket, &wsabuf, 1, &dwRecvByte, &Flags, (LPWSAOVERLAPPED)PS, NULL))
            {
                int ercode = WSAGetLastError();
                if (ercode != WSA_IO_PENDING && ercode != WSAEFAULT)
                {
                    // If receiving data failed, close the server and release resources
                    onServerFunc(this, PS->hSocket, tcp_server_close, 0, 0);
                    delete[] PS->data;
                    delete PS;
                    PS = NULL;
                }
                return;
            }
            return;
        }

        DWORD size = *((DWORD *)(PS->data));
        if (size > 65536000)
        {
            // If data size exceeds the limit, close the server and release resources
            onServerFunc(this, PS->hSocket, tcp_server_close, 0, 0);
            delete[] PS->data;
            delete PS;
            PS = NULL;
            return;
        }

        if (PS->offset < sizeof(DWORD) + size)
        {
            char* newData = new char[sizeof(DWORD) + size];

            if (!newData) {
                // If memory allocation failed, close the server and release resources
                onServerFunc(this, PS->hSocket, tcp_server_close, 0, 0);
                delete[] PS->data;
                delete PS;
                PS = NULL;
                return;
            }

            delete[] PS->data;
            PS->data = newData;
            PS->size = sizeof(DWORD) + size;
            PS->offset = sizeof(DWORD);
            memcpy(PS->data, &size, sizeof(DWORD));

            WSABUF wsabuf;
            wsabuf.buf = PS->data + PS->offset;
            wsabuf.len = PS->size - PS->offset;
            DWORD dwRecvByte = 0;
            DWORD Flags = 0;
            if (WSARecv(PS->hSocket, &wsabuf, 1, &dwRecvByte, &Flags, (LPWSAOVERLAPPED)PS, NULL))
            {
                int ercode = WSAGetLastError();
                if (ercode != WSA_IO_PENDING && ercode != WSAEFAULT)
                {
                    // If receiving data failed, close the server and release resources
                    onServerFunc(this, PS->hSocket, tcp_server_close, 0, 0);
                    delete[] PS->data;
                    delete PS;
                    PS = NULL;
                }
                return;
            }
            return;
        }

        // Data processing complete, callback handler
        if (PS->size > sizeof(DWORD))
        {
            onServerFunc(this, PS->hSocket, tcp_server_recv, PS->data + sizeof(DWORD), PS->size - sizeof(DWORD));
        }

        // Reset buffer for next data
        delete[] PS->data;
        PS->data = new char[sizeof(DWORD)];
        PS->size = sizeof(DWORD);
    }
    else
    {
        // If no pairing, call the processing function directly
        onServerFunc(this, PS->hSocket, tcp_server_recv, PS->data, PS->bytes);
    }

    // Reset offset and state, prepare for next receive
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

    // Start next data reception
    DWORD dwRecvBytes = 0;
    DWORD Flags = 0;
    if (WSARecv(PS->hSocket, &wsabuf, 1, &dwRecvBytes, &Flags, (LPWSAOVERLAPPED)PS, NULL))
    {
        int code = WSAGetLastError();
        if (code != WSA_IO_PENDING && code != WSAEFAULT)
        {
            // If receiving data failed, close the server and release resources
            onServerFunc(this, PS->hSocket, tcp_server_close, 0, 0);
            delete[] PS->data;
            delete PS;
            PS = NULL;

        }
    }
}



int SERVER::doSend(SOCKET hSocket, char *data, DWORD size)
{
	// 检查要发送的数据大小是否超过最大允许大小
	if (size > 65536000)
	{
		return 0; // 如果超过，返回0表示失败
	}

	// 分配并初始化一个新的 SERVER_ST 实例用于发送操作
	SERVER_ST *Socket_ST = new SERVER_ST;
	memset(Socket_ST, 0, sizeof(SERVER_ST));
	Socket_ST->instance = this;			// 将当前 SERVER 实例指针赋值给 Socket_ST 的 so 字段
	Socket_ST->state = tcp_server_send; // 将状态设置为发送

	WSABUF wsabuf;

	// 检查是否启用了缓冲区大小处理
	if (m_mate)
	{
		// 分配一个新的缓冲区，包括数据大小
		Socket_ST->data = new char[sizeof(DWORD) + size];
		Socket_ST->size = sizeof(DWORD) + size;
		wsabuf.buf = Socket_ST->data;
		wsabuf.len = Socket_ST->size;
		// 将数据大小和实际数据复制到缓冲区中
		memcpy(wsabuf.buf, &size, sizeof(DWORD));
		memcpy(wsabuf.buf + sizeof(DWORD), data, size);
	}
	else
	{
		// 如果未启用缓冲区大小处理，直接使用提供的缓冲区
		wsabuf.buf = data;
		wsabuf.len = size;
	}

	Socket_ST->offset = 0; // 初始化缓冲区偏移量

	// 发起一个异步发送操作
	if (WSASend(hSocket, &wsabuf, 1, &Socket_ST->bytes, 0, (LPWSAOVERLAPPED)Socket_ST, NULL))
	{
		int ercode = WSAGetLastError();
		// 处理特定错误
		if (ercode != WSA_IO_PENDING)
		{
			// 如果发送操作失败，清理资源
			delete[] Socket_ST->data;
			Socket_ST->data = NULL;
			delete Socket_ST;
			Socket_ST = NULL;
			return 1; // 返回1表示失败
		}
	}

	return 0; // 返回0表示发送操作成功启动
}

int SERVER::doSend_sync(SOCKET hSocket, char *data, DWORD size)
{
	// 检查数据大小是否超过限制
	if (size > 65536000)
	{
		return 0; // 如果超过限制，返回0表示发送失败
	}

	// 如果启用了特定的协议处理
	if (m_mate)
	{
		// 将数据大小信息复制到缓冲区前面
		memcpy(data, &size, sizeof(DWORD));
		// 将实际数据复制到缓冲区后面
		memcpy(data + sizeof(DWORD), data, size);
		// 发送带有数据大小信息的数据
		if (send(hSocket, data, size + sizeof(DWORD), 0))
		{
			return 0; // 发送失败，返回0
		}
	}
	else
	{
		// 直接发送数据
		if (send(hSocket, data, size, 0))
		{
			return 0; // 发送失败，返回0
		}
	}

	return 1; // 发送成功，返回1
}

void SERVER::OnSend(bool ercode, PS_SERVER PS)
{
	SOCKET hSocket = PS->hSocket; // 获取操作使用的套接字

	delete[] PS->data; // 释放用户操作结构体中的缓冲区
	PS->data = NULL;   // 将缓冲区指针置空
	delete PS;		   // 释放用户操作结构体对象
	PS = NULL;		   // 将结构体指针置空

	if (ercode)
	{
		closesocket(hSocket);								// 如果发生错误，关闭套接字
		onServerFunc(this, hSocket, tcp_server_stop, 0, 0); // 通知服务器函数连接停止
		hSocket = INVALID_SOCKET;							// 将套接字置为无效
	}
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
	// 构造函数，初始化类对象
	CLIENT(void);

	// 析构函数，销毁类对象，释放资源
	~CLIENT(void);

	// 初始化套接字连接
	// 参数:
	// - host: 服务器地址
	// - port: 服务器端口号
	// - nIs: 是否为非阻塞模式
	// - time: 超时时间
	// 返回值: 初始化是否成功的状态码
	int Init(char *host, unsigned short port, BOOL nIs, int time);

	// 连接回调函数
	// 参数:
	// - ercode: 连接是否成功
	// - op: 客户端操作结构指针
	void OnConnect(bool ercode, PS_CLIENT op);

	// 关闭回调函数
	// 参数:
	// - ercode: 关闭是否成功
	// - op: 客户端操作结构指针
	void OnClose(bool ercode, PS_CLIENT op);

	// 接收回调函数
	// 参数:
	// - ercode: 接收是否成功
	// - op: 客户端操作结构指针
	void OnRecv(bool ercode, PS_CLIENT op);

	// 接收数据
	// 参数:
	// - op: 客户端操作结构指针
	// 返回值: 接收操作的状态码
	int SoRecv(PS_CLIENT op);

	// 关闭套接字
	// 返回值: 关闭操作的状态码
	int Close();

	// 发送数据
	// 参数:
	// - buf: 发送数据的缓冲区
	// - cb: 发送数据的字节数
	// - isok: 发送操作的标志
	// - outbuf: 输出缓冲区
	// - outtime: 超时时间
	// 返回值: 发送操作的状态码
	int doSend(char *data, DWORD cb, int isok, char *outbuf, int outtime);

	// 发送回调函数
	// 参数:
	// - ercode: 发送是否成功
	// - op: 客户端操作结构指针
	void OnSend(bool ercode, PS_CLIENT op);

	// 获取当前套接字
	// 返回值: 当前套接字
	SOCKET get_socket()
	{
		return m_hSocket;
	}

public:
	// 套接字句柄
	SOCKET m_hSocket;

	// 同步或异步模式标志
	BOOL m_mate;

	// 缓冲区的满载标志
	int m_full;

	// 数据缓冲区
	char *m_data;
};

CLIENT::CLIENT(void)
{
	m_hSocket = INVALID_SOCKET;
}
CLIENT::~CLIENT(void)
{
	m_hSocket = INVALID_SOCKET;
}

int CLIENT::Init(char *host, unsigned short port, BOOL mate, int time)
{
	m_mate = mate;
	// 创建一个套接字用于客户端通信
	m_hSocket = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, 0, 0, WSA_FLAG_OVERLAPPED);
	if (INVALID_SOCKET == m_hSocket)
	{
		// 如果创建套接字失败，返回错误代码
		return WSAGetLastError();
	}

	// 将套接字与I/O完成端口关联
	if (CreateIoCompletionPort((HANDLE)m_hSocket, hEvent_Client, 0, 0) == NULL)
	{
		// 如果关联失败，关闭套接字并返回错误代码
		Close();
		return GetLastError();
	}

	// 初始化 sockaddr_in 结构体以绑定套接字
	sockaddr_in pSockaddr;
	pSockaddr.sin_family = AF_INET; // 设置地址族为AF_INET
	pSockaddr.sin_addr.s_addr = 0;	// 使用任何可用的本地地址

	pSockaddr.sin_port = 0; // 使用任何可用的端口

	// 绑定套接字到本地地址
	if (bind(m_hSocket, (SOCKADDR *)&pSockaddr, sizeof(pSockaddr)) == SOCKET_ERROR)
	{
		// 如果绑定失败，关闭套接字并返回错误代码
		Close();
		return WSAGetLastError();
	}

	// 存储mate参数

	// 解析主机地址并设置用于连接的 sockaddr_in 结构体
	pSockaddr.sin_family = AF_INET;

	pSockaddr.sin_addr.s_addr = inet_addr(host);
	pSockaddr.sin_port = htons(port);

	// 将套接字设置为非阻塞模式
	unsigned long ul = 1;
	ioctlsocket(m_hSocket, FIONBIO, (unsigned long *)&ul);

	// 发起与服务器的连接
	connect(m_hSocket, (sockaddr *)&pSockaddr, sizeof(sockaddr));

	// 设置连接超时时间
	struct timeval timeout;
	fd_set r;
	FD_ZERO(&r);		   // 清空文件描述符集
	FD_SET(m_hSocket, &r); // 将套接字加入文件描述符集
	timeout.tv_sec = time; // 设置秒级超时
	timeout.tv_usec = 0;   // 设置微秒级超时

	// 使用select等待连接建立或超时
	if (select(m_hSocket, 0, &r, 0, &timeout) <= 0)
	{
		// 如果连接失败或超时，关闭套接字并返回错误代码
		Close();
		return 1;
	}

	// 为连接分配并初始化一个CLIENT_ST结构体
	CLIENT_ST *Socket_ST = new CLIENT_ST;
	memset(Socket_ST, 0, sizeof(CLIENT_ST));
	Socket_ST->instance = this;			 // 设置指向当前对象的指针
	Socket_ST->state = tcp_client_connt; // 设置初始状态为连接状态
	Socket_ST->data = NULL;				 // 初始化缓冲区指针
	Socket_ST->size = 0;				 // 初始化缓冲区大小
	Socket_ST->offset = 0;				 // 初始化缓冲区偏移量

	// 将完成状态发布到I/O完成端口
	PostQueuedCompletionStatus(hEvent_Client, 0, 0, (LPOVERLAPPED)Socket_ST);

	// 返回0表示成功
	return 0;
}

void CLIENT::OnConnect(bool ercode, PS_CLIENT Socket_ST)
{
	// 设置套接字选项（这里的0x7010是一个自定义选项，具体含义取决于上下文）
	setsockopt(m_hSocket, SOL_SOCKET, 0x7010, NULL, 0);

	// 调用客户端连接回调函数，通知连接成功
	onClientFunc(this, m_hSocket, tcp_client_connt, NULL, 0);

	// 如果有错误码，关闭连接并返回
	if (ercode)
	{
		OnClose(ercode, Socket_ST); // 关闭连接并释放资源
		return;
	}

	// 删除旧的缓冲区
	delete[] Socket_ST->data;

	// 根据m_mate的值分配新的缓冲区
	if (m_mate)
	{
		// 如果m_mate为true，分配sizeof(DWORD)大小的缓冲区
		Socket_ST->data = new char[sizeof(DWORD)];
		Socket_ST->size = sizeof(DWORD);
	}
	else
	{
		// 如果m_mate为false，分配pack大小的缓冲区
		Socket_ST->data = new char[pack];
		Socket_ST->size = pack;
	}

	// 设置状态为接收数据
	Socket_ST->state = tcp_client_recv;
	// 将缓冲区偏移量重置为0
	Socket_ST->offset = 0;

	// 尝试接收数据，如果接收失败，关闭连接并返回
	if (1 == SoRecv(Socket_ST))
	{
		OnClose(ercode, Socket_ST); // 关闭连接并释放资源
		return;
	}
}
void CLIENT::OnRecv(bool ercode, PS_CLIENT Socket_ST)
{
	// 如果发生错误，关闭连接并返回
	if (ercode)
	{
		OnClose(ercode, Socket_ST); // 关闭连接并释放资源
		return;
	}

	// 如果 m_mate 为 true，进行以下操作
	if (m_mate)
	{
		// 更新缓冲区的偏移量
		Socket_ST->offset += Socket_ST->bytes;

		// 如果缓冲区未填满，继续接收数据
		if (Socket_ST->offset < Socket_ST->size)
		{
			// 尝试继续接收数据，如果失败则关闭连接
			if (1 == SoRecv(Socket_ST))
			{
				OnClose(ercode, Socket_ST); // 关闭连接并释放资源
				return;
			}
			return;
		}

		// 获取数据大小
		DWORD size = *((DWORD *)(Socket_ST->data));

		// 如果数据大小超过最大限制，关闭连接
		if (size > 65536000)
		{
			OnClose(ercode, Socket_ST); // 关闭连接并释放资源
			return;
		}

		// 如果缓冲区未填满，重新分配缓冲区并继续接收数据
		if (Socket_ST->offset < DWORD(sizeof(DWORD)) + size)
		{
			delete[] Socket_ST->data;						  // 删除旧的缓冲区
			Socket_ST->data = new char[sizeof(DWORD) + size]; // 分配新的缓冲区
			Socket_ST->size = sizeof(DWORD) + size;
			Socket_ST->offset = sizeof(DWORD);
			memcpy(Socket_ST->data, &size, sizeof(DWORD)); // 将数据大小复制到缓冲区
			// 尝试继续接收数据，如果失败则关闭连接
			if (1 == SoRecv(Socket_ST))
			{
				OnClose(ercode, Socket_ST); // 关闭连接并释放资源
				return;
			}
			return;
		}

		// 如果缓冲区内有数据，并且 m_full 大于 0，复制数据到 m_data 并重置 m_full
		if (Socket_ST->size - sizeof(DWORD) > 0)
		{
			if (m_full > 0)
			{
				memcpy(m_data, Socket_ST->data + sizeof(DWORD), Socket_ST->size - sizeof(DWORD));
				m_full = 0;
			}

			// 调用客户端接收函数
			onClientFunc(this, m_hSocket, tcp_client_recv, Socket_ST->data + sizeof(DWORD), Socket_ST->size - sizeof(DWORD));
		}

		// 释放当前缓冲区并分配新的缓冲区
		delete[] Socket_ST->data;
		Socket_ST->data = new char[sizeof(DWORD)];
		Socket_ST->size = sizeof(DWORD);
	}
	else
	{
		// 如果 m_mate 为 false，直接处理接收到的数据
		if (m_full > 0)
		{
			memcpy(m_data, Socket_ST->data, Socket_ST->bytes); // 复制数据到 m_data
		}

		// 调用客户端接收函数
		onClientFunc(this, m_hSocket, tcp_client_recv, Socket_ST->data, Socket_ST->bytes);
		m_full = 0; // 重置 m_full
	}

	// 重置缓冲区偏移量
	Socket_ST->offset = 0;

	// 继续接收数据，如果失败则关闭连接
	if (1 == SoRecv(Socket_ST))
	{
		OnClose(ercode, Socket_ST); // 关闭连接并释放资源
		return;
	}
}

int CLIENT::SoRecv(PS_CLIENT Socket_ST)
{
	// 设置当前CLIENT实例指针
	Socket_ST->instance = this;
	// 设置状态为接收数据
	Socket_ST->state = tcp_client_recv;

	// 设置WSABUF结构，用于接收数据
	WSABUF wsabuf;
	wsabuf.buf = Socket_ST->data + Socket_ST->offset; // 缓冲区的起始位置
	wsabuf.len = Socket_ST->size - Socket_ST->offset; // 缓冲区的长度

	// 设置标志为0
	DWORD Flg = 0;

	// 调用WSARecv函数异步接收数据
	if (WSARecv(m_hSocket, &wsabuf, 1, &Socket_ST->bytes, &Flg, (LPWSAOVERLAPPED)Socket_ST, NULL))
	{
		// 如果WSARecv返回非零值，获取错误码
		int ercode = WSAGetLastError();

		// 如果错误码是WSAEFAULT，表示缓冲区不正确，返回0表示成功
		if (ercode == WSAEFAULT)
		{
			return 0;
		}
		// 如果错误码不是WSA_IO_PENDING，表示接收操作没有挂起，返回1表示失败
		else if (ercode != WSA_IO_PENDING)
		{
			return 1;
		}
	}

	// 返回0表示成功
	return 0;
}

void CLIENT::OnClose(bool ercode, PS_CLIENT Socket_ST)
{
	// 删除缓冲区
	delete[] Socket_ST->data;
	Socket_ST->data = NULL;
	// 删除CLIENT_ST结构体
	delete Socket_ST;
	Socket_ST = NULL;
	// 调用客户端关闭回调函数，通知连接关闭
	onClientFunc(this, m_hSocket, tcp_client_stop, NULL, 0);
	// 关闭套接字
	Close();
}

int CLIENT::Close()
{
	// 关闭套接字
	closesockets(m_hSocket);
	m_hSocket = INVALID_SOCKET;
	return 0;
}

int CLIENT::doSend(char *data, DWORD size, int full, char *recv, int timeout)
{
	// 检查发送数据大小是否超过限制
	if (size > 65536000)
	{
		return 0; // 如果超过限制，返回0表示失败
	}

	// 设置成员变量m_full和m_data
	m_full = full;
	m_data = recv;

	// 分配并初始化一个CLIENT_ST结构体
	CLIENT_ST *Socket_ST = new CLIENT_ST;
	memset(Socket_ST, 0, sizeof(CLIENT_ST));
	Socket_ST->instance = this;
	Socket_ST->state = tcp_client_send;

	// 设置WSABUF结构，用于发送数据
	WSABUF wsabuf;

	// 如果m_mate为true，构造发送缓冲区
	if (m_mate)
	{
		Socket_ST->data = new char[sizeof(DWORD) + size];
		Socket_ST->size = sizeof(DWORD) + size;
		wsabuf.buf = Socket_ST->data;
		wsabuf.len = Socket_ST->size;
		memcpy(wsabuf.buf, &size, sizeof(DWORD));		// 复制数据大小
		memcpy(wsabuf.buf + sizeof(DWORD), data, size); // 复制实际数据
	}
	else
	{
		// 如果m_mate为false，直接使用传入的缓冲区
		Socket_ST->data = data;
		Socket_ST->size = size;
		wsabuf.buf = Socket_ST->data;
		wsabuf.len = Socket_ST->size;
	}

	// 调用WSASend函数异步发送数据
	if (WSASend(m_hSocket, &wsabuf, 1, &Socket_ST->bytes, 0, (LPWSAOVERLAPPED)Socket_ST, NULL))
	{
		int ercode = WSAGetLastError();
		// 如果错误码不是WSA_IO_PENDING，表示发送操作失败
		if (ercode != WSA_IO_PENDING)
		{
			delete[] Socket_ST->data; // 释放缓冲区
			delete Socket_ST;		  // 删除CLIENT_ST结构体
			return 1;				  // 返回1表示失败
		}
	}

	int time = 0;
	// 如果timeout小于等于0，将其设置为2秒
	if (timeout <= 0)
	{
		timeout = 2;
	}
	// 将timeout转换为毫秒
	timeout = timeout * 1000;

	// 等待发送完成或超时
	while (1 == m_full)
	{
		time++;
		// 如果等待时间超过指定的超时时间，重置m_full和m_data并退出循环
		if (time > timeout)
		{
			m_full = 0;
			m_data = NULL;
			break;
		}
		Sleep(1); // 每次循环等待1毫秒
	}

	return 0; // 返回0表示成功
}

void CLIENT::OnSend(bool ercode, PS_CLIENT Socket_ST)
{
	// 如果存在错误码，调用OnClose关闭连接并返回
	if (ercode)
	{
		OnClose(ercode, Socket_ST);
		return;
	}

	// 如果m_mate为true，删除缓冲区和CLIENT_ST结构体
	if (m_mate)
	{
		delete[] Socket_ST->data;
		delete Socket_ST;
	}
}

unsigned __stdcall Worker_server(void *pParam)
{
	while (true)
	{
		ULONG bytes = 0;
		ULONG_PTR key = 0;
		SERVER_ST *Socket_ST = nullptr;
		bool error = false;

		if (!GetQueuedCompletionStatus(hEvent_Server, &bytes, &key, (LPOVERLAPPED *)&Socket_ST, INFINITE))
		{
			error = true;
		}

		SERVER *so = Socket_ST->instance;
		if (Socket_ST->state == tcp_server_recv && bytes <= 0)
		{
			error = true;
		}

		Socket_ST->bytes = bytes;

		if (so->m_stop)
		{
			so->OnSend(true, Socket_ST);
			continue;
		}

		switch (Socket_ST->state)
		{
		case tcp_server_connt:
			so->OnAccept(error, Socket_ST);
			break;
		case tcp_server_recv:
			so->OnRecv(error, Socket_ST);
			break;
		case tcp_server_send:
			so->OnSend(error, Socket_ST);
			break;
		default:
			// Handle unexpected state
			break;
		}
	}

	_endthreadex(0);
	return 0;
}

// Client worker function
unsigned __stdcall Worker_client(void *pParam)
{
	while (true)
	{
		ULONG bytes = 0;
		ULONG_PTR key = 0;
		CLIENT_ST *Socket_ST = nullptr;
		bool error = false;

		if (!GetQueuedCompletionStatus(hEvent_Client, &bytes, &key, (LPOVERLAPPED *)&Socket_ST, INFINITE))
		{
			error = true;
		}

		CLIENT *so = Socket_ST->instance;
		if (Socket_ST->state == tcp_client_recv && bytes <= 0)
		{
			error = true;
		}

		Socket_ST->bytes = bytes;

		switch (Socket_ST->state)
		{
		case tcp_client_connt:
			so->OnConnect(error, Socket_ST);
			break;
		case tcp_client_recv:
			so->OnRecv(error, Socket_ST);
			break;
		case tcp_client_send:
			so->OnSend(error, Socket_ST);
			break;
		default:
			// Handle unexpected state
			break;
		}
	}

	_endthreadex(0);
	return 0;
}

extern "C" __declspec(dllexport) int __stdcall socket_init(onServer_ex nFun, onClient_ex cFun)
{
	WSAData wsa;
	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
	{
		return WSAGetLastError();
	}

	onServerFunc = nFun;
	onClientFunc = cFun;

	hEvent_Server = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
	if (hEvent_Server == NULL)
	{
		return GetLastError();
	}

	hEvent_Client = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
	if (hEvent_Client == NULL)
	{
		CloseHandle(hEvent_Server);
		return GetLastError();
	}

	SYSTEM_INFO info;
	GetSystemInfo(&info);
	worker = info.dwNumberOfProcessors + 2;
	if (worker < 5)
	{
		worker = 5;
	}

	for (int i = 0; i < worker; i++)
	{
		HANDLE threadHandle = (HANDLE)_beginthreadex(NULL, 0, &Worker_server, NULL, 0, NULL);
		if (threadHandle != NULL)
		{
			CloseHandle(threadHandle);
		}

		threadHandle = (HANDLE)_beginthreadex(NULL, 0, &Worker_client, NULL, 0, NULL);
		if (threadHandle != NULL)
		{
			CloseHandle(threadHandle);
		}
	}

	return 0;
}

extern "C" __declspec(dllexport) int __stdcall socket_server(char *host, unsigned short port, int mete)
{
	SERVER *dServer = new SERVER;
	if (0 != dServer->Init(host, port, mete))
	{
		delete dServer;
		dServer = NULL;
		return 0;
	}
	return 0;
	// 编译的时候需要注释上面返回 并且返回真实指针地址
	// return (int)dServer;
}
extern "C" __declspec(dllexport) int __stdcall socket_server_send(HANDLE hSocket, SOCKET client_so, char *buf, int len)
{
	return ((SERVER *)hSocket)->doSend(client_so, buf, len);
}
extern "C" __declspec(dllexport) int __stdcall socket_server_sends(HANDLE hSocket, SOCKET client_so, char *buf, int len)
{
	return ((SERVER *)hSocket)->doSend_sync(client_so, buf, len);
}
extern "C" __declspec(dllexport) int __stdcall socket_server_get_port(HANDLE hSocket)
{
	return ((SERVER *)hSocket)->get_port();
}
char *__stdcall socket_server_get_ip(HANDLE hSocket, SOCKET client_so)
{
	return ((SERVER *)hSocket)->get_ip(client_so);
}
SOCKET __stdcall socket_server_get_socket(HANDLE hSocket)
{
	return ((SERVER *)hSocket)->get_socket();
}
extern "C" __declspec(dllexport) int __stdcall socket_server_close(SOCKET hSocket)
{
	return closesockets(hSocket);
}

extern "C" __declspec(dllexport) int __stdcall socket_server_stop(HANDLE hSocket)
{
	if (IsBadReadPtr(hSocket, 4) != 0)
	{
		return 0;
	}
	SERVER *dServer = ((SERVER *)hSocket);
	dServer->Close();
	delete dServer;
	dServer = NULL;
	return 0;
}

extern "C" __declspec(dllexport) int __stdcall socket_client(char *host, unsigned short port, BOOL nIs, int time)
{
	CLIENT *dClient = new CLIENT;
	if (0 != dClient->Init(host, port, nIs, time))
	{
		delete dClient;
		dClient = NULL;
		return 0;
	}
	return 0;
	// 编译的时候需要注释上面返回 并且返回真实指针地址
	// return (int)dClient;
}
extern "C" __declspec(dllexport) int __stdcall socket_client_send(HANDLE hSocket, char *buf, int len, int isok, char *outbuf, int outtime)
{
	return ((CLIENT *)hSocket)->doSend(buf, len, isok, outbuf, outtime);
}

extern "C" __declspec(dllexport) int __stdcall socket_client_close(HANDLE hSocket)
{
	return ((CLIENT *)hSocket)->Close();
}

extern "C" __declspec(dllexport) int __stdcall socket_client_get(HANDLE hSocket)
{
	return ((CLIENT *)hSocket)->get_socket();
}

void __stdcall ServerCallback(HANDLE Server, SOCKET so, int type, char *data, int size)
{
    if (type == 1)
    {
        printf("ServerCallback  Connect \n");

        // Sending 70MB of data
       
        int totalBytesToSend = 204800;

        char *sendData = (char *)malloc(totalBytesToSend);
        if (sendData == NULL)
        {
            printf("Failed to allocate memory for sendData\n");
            return;
        }

        memset(sendData, 'A', totalBytesToSend); // Fill with 'A's for demonstration

        socket_server_send(Server, so, sendData, totalBytesToSend);

        free(sendData);
    }
    else if (type == 2)
    {
        // printf("Received data: %.*s\n", size, data);
        printf("Received data: %d\n", size);
    }
}

void __stdcall ClientCallback(HANDLE Client, SOCKET so, int type, char *data, int size)
{
    if (type == 1)
    {
        printf("ClientCallback  Connect \n");

        // Sending 70MB of data
        
        int totalBytesToSend = 204800;

        char *sendData = (char *)malloc(totalBytesToSend);
        if (sendData == NULL)
        {
            printf("Failed to allocate memory for sendData\n");
            return;
        }

        memset(sendData, 'B', totalBytesToSend); // Fill with 'B's for demonstration

        socket_client_send(Client, sendData, totalBytesToSend, 0, 0, 0);

        free(sendData);
    }
    else if (type == 2)
    {
        // printf("Received data: %.*s\n", size, data);
        printf("Received data: %d\n", size);
    }
}
int __stdcall main()
{
	if (socket_init(ServerCallback, ClientCallback) == 0)
	{
		SERVER *s = new SERVER;
		printf("S %d \n", s->Init((char *)"0.0.0.0", 8800, 0));
		CLIENT *c = new CLIENT;
		printf("C %d \n", c->Init((char *)"127.0.0.1", 8800, 0, 30));
		Sleep(1000 * 60 * 60 * 30);
	}
	return 0;
}
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
