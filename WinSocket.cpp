#include <SDKDDKVer.h>
#include <WinSock2.h>
#include <mswsock.h>
#include <MSTcpIP.h>
#include <process.h>
#include <stdio.h>
#include <map>
int worker = 0;
int cache = 8192;
#define io_connt 1
#define io_recv 2
#define io_stop 3
#define io_send 4
#define io_close 5

typedef void(__stdcall *onSocket)(HANDLE Server, SOCKET hSocket, int type, char *data, int size);
HANDLE hServer;
HANDLE hClient;
HANDLE hEvent_Server = NULL;
HANDLE hEvent_Client = NULL;
onSocket onServerFunc = NULL;
onSocket onClientFunc = NULL;

char *gethostnames(SOCKET socket)
{
	sockaddr_in pSockaddr;
	int size = sizeof(pSockaddr);
	getsockname(socket, (sockaddr *)&pSockaddr, &size);
	return inet_ntoa(pSockaddr.sin_addr);
}

int closesockets(SOCKET hSocket)
{
	if (hSocket == INVALID_SOCKET)
	{
		return 0;
	}

	struct linger lingerStruct;
	lingerStruct.l_onoff = 1;
	lingerStruct.l_linger = 0;

	int code = setsockopt(hSocket, SOL_SOCKET, SO_LINGER, (char *)&lingerStruct, sizeof(lingerStruct));

	code = shutdown(hSocket, SD_BOTH);

	return closesocket(hSocket);
}

class SERVER;
typedef struct SERVER_ST
{
	OVERLAPPED Socket_ST;
	SERVER *instance;
	int state;
	SOCKET hSocket;
	char *data;
	DWORD bytes;
	DWORD size;
	DWORD offset;
} PX_SERVER, *PS_SERVER;
class SERVER
{
public:
	SERVER(void);
	~SERVER(void);

public:
	int Init(char *host, unsigned short port, int mete);
	int Accept();
	void onAccept(bool stop, PS_SERVER Socket_ST);
	void onRecv(bool stop, PS_SERVER Socket_ST);
	int Close();
	int send_async(SOCKET hSocket, char *data, DWORD size);
	int send_sync(SOCKET hSocket, char *data, DWORD size);
	void onSend(bool stop, PS_SERVER Socket_ST);
	SOCKET get_socket()
	{
		return m_hSocket;
	}


public:
	SOCKET m_hSocket;
	BOOL m_mate;
	BOOL m_stop;
};

SERVER::SERVER(void)
{
	m_stop = FALSE;
	m_hSocket = INVALID_SOCKET;
}

SERVER::~SERVER(void)
{
	m_hSocket = INVALID_SOCKET;
}

int SERVER::Init(char *host, unsigned short port, int mete)
{
	m_mate = mete;

	m_hSocket = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, 0, 0, WSA_FLAG_OVERLAPPED);
	if (INVALID_SOCKET == m_hSocket)
	{
		return WSAGetLastError();
	}

	if (CreateIoCompletionPort((HANDLE)m_hSocket, hEvent_Server, 0, 0) == NULL)
	{
		Close();
		return GetLastError();
	}

	sockaddr_in pSockaddr;
	pSockaddr.sin_family = AF_INET;
	pSockaddr.sin_addr.s_addr = inet_addr(host);
	pSockaddr.sin_port = htons(port);

	if (bind(m_hSocket, (SOCKADDR *)&pSockaddr, sizeof(pSockaddr)) == SOCKET_ERROR)
	{
		Close();
		return WSAGetLastError();
	}

	if (listen(m_hSocket, worker) == SOCKET_ERROR)
	{
		Close();
		return WSAGetLastError();
	}

	SERVER_ST *Socket_ST = new SERVER_ST;
	memset(Socket_ST, 0, sizeof(SERVER_ST));
	Socket_ST->data = new char[cache];
	Socket_ST->instance = this;
	Socket_ST->size = cache;
	Socket_ST->offset = 0;
	Socket_ST->state = io_connt;
	Socket_ST->hSocket = INVALID_SOCKET;
	Socket_ST->hSocket = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, 0, 0, WSA_FLAG_OVERLAPPED);

	if (Socket_ST->hSocket == INVALID_SOCKET)
	{
		delete[] Socket_ST->data;
		Socket_ST->data = NULL;
		delete Socket_ST;
		Socket_ST = NULL;
		Close();
		return WSAGetLastError();
	}

	BOOL reuseAddr = TRUE;
	setsockopt(Socket_ST->hSocket, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuseAddr, sizeof(BOOL));
	int recvBufferSize = 4096;
	setsockopt(Socket_ST->hSocket, SOL_SOCKET, SO_RCVBUF, (const char *)&recvBufferSize, sizeof(int));
	int sendBufferSize = 0;
	setsockopt(Socket_ST->hSocket, SOL_SOCKET, SO_SNDBUF, (const char *)&sendBufferSize, sizeof(int));

	if (CreateIoCompletionPort((HANDLE)Socket_ST->hSocket, hEvent_Server, 0, 0) == NULL)
	{
		closesocket(Socket_ST->hSocket);
		Socket_ST->hSocket = INVALID_SOCKET;
		delete[] Socket_ST->data;
		Socket_ST->data = NULL;
		delete Socket_ST;
		Socket_ST = NULL;
		Close();
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
		Close();
		return 2;
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
		Close();
		return 3;
	}

	return 0;
}

int SERVER::Close()
{

	m_stop = TRUE;
	closesockets(m_hSocket);
	m_hSocket = INVALID_SOCKET;

	return 0;
}

int SERVER::Accept()
{

	SERVER_ST *Socket_ST = new SERVER_ST;
	memset(Socket_ST, 0, sizeof(SERVER_ST));

	Socket_ST->data = new char[cache];
	Socket_ST->instance = this;
	Socket_ST->size = cache;
	Socket_ST->offset = 0;
	Socket_ST->state = io_connt;
	Socket_ST->hSocket = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, 0, 0, WSA_FLAG_OVERLAPPED);

	if (INVALID_SOCKET == Socket_ST->hSocket)
	{

		delete[] Socket_ST->data;
		Socket_ST->data = NULL;
		delete Socket_ST;
		Socket_ST = NULL;
		return WSAGetLastError();
	}

	BOOL reuseAddr = TRUE;
	setsockopt(Socket_ST->hSocket, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuseAddr, sizeof(BOOL));
	int recvBufferSize = 4096;
	setsockopt(Socket_ST->hSocket, SOL_SOCKET, SO_RCVBUF, (const char *)&recvBufferSize, sizeof(int));
	int sendBufferSize = 0;
	setsockopt(Socket_ST->hSocket, SOL_SOCKET, SO_SNDBUF, (const char *)&sendBufferSize, sizeof(int));

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

		closesocket(Socket_ST->hSocket);
		Socket_ST->hSocket = INVALID_SOCKET;
		PostQueuedCompletionStatus(hEvent_Server, 0, 0, (LPOVERLAPPED)Socket_ST);
		delete[] Socket_ST->data;
		Socket_ST->data = NULL;
		delete Socket_ST;
		Socket_ST = NULL;
		return 2;
	}

	bytesReturned = 0;
	if (lpfnAcceptEx(m_hSocket, Socket_ST->hSocket, Socket_ST->data, 0, sizeof(sockaddr) + 16, sizeof(sockaddr) + 16, &bytesReturned, (LPOVERLAPPED)Socket_ST))
	{

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

void SERVER::onAccept(bool stop, PS_SERVER PS)
{

	while (0 != Accept())
	{
		Sleep(1);
	}

	setsockopt(PS->hSocket, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, (char *)&m_hSocket, sizeof(SOCKET));

	tcp_keepalive keepAliveParams;
	keepAliveParams.onoff = 1;
	keepAliveParams.keepalivetime = 1000 * 30;
	keepAliveParams.keepaliveinterval = 1000 * 5;
	DWORD bytesReturned = 0;
	DWORD Flags = 0;

	WSAIoctl(PS->hSocket, SIO_KEEPALIVE_VALS, &keepAliveParams, sizeof(keepAliveParams), NULL, 0, &bytesReturned, NULL, NULL);

	onServerFunc(this, PS->hSocket, io_connt, NULL, 0);
	if (stop)
	{
		onServerFunc(this, PS->hSocket, io_close, NULL, 0);
		closesocket(PS->hSocket);
		PS->hSocket = INVALID_SOCKET;
		delete[] PS->data;
		PS->data = NULL;
		delete PS;
		PS = NULL;
		return;
	}

	PS->state = io_recv;

	WSABUF wsabuf;
	if (m_mate)
	{

		delete[] PS->data;
		PS->offset = 0;
		PS->data = new char[sizeof(DWORD)];
		PS->size = sizeof(DWORD);
		wsabuf.buf = PS->data + PS->offset;
		wsabuf.len = PS->size - PS->offset;
	}
	else
	{
		wsabuf.buf = PS->data;
		wsabuf.len = cache;
	}
	bytesReturned = 0;
	Flags = 0;
	if (WSARecv(PS->hSocket, &wsabuf, 1, &bytesReturned, &Flags, (LPWSAOVERLAPPED)PS, NULL))
	{
		int code = WSAGetLastError();

		if (code == WSAEFAULT)
		{
			return;
		}

		else if (code != WSA_IO_PENDING)
		{
			onServerFunc(this, PS->hSocket, io_close, NULL, 0);
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

void SERVER::onRecv(bool stop, PS_SERVER PS)
{
	if (stop)
	{
		onServerFunc(this, PS->hSocket, io_close, 0, 0);
		delete[] PS->data;
		PS->data = NULL;
		delete PS;
		PS = NULL;
		return;
	}
	PS->offset += PS->bytes;
	DWORD dwRecvByte = 0;
	DWORD Flags = 0;
	if (m_mate)
	{
		if (PS->offset < PS->size)
		{
			PS->state = io_recv;
			WSABUF wsabuf;
			wsabuf.buf = PS->data + PS->offset;
			wsabuf.len = PS->size - PS->offset;
			dwRecvByte = 0;
			Flags = 0;
			if (WSARecv(PS->hSocket, &wsabuf, 1, &dwRecvByte, &Flags, (LPWSAOVERLAPPED)PS, NULL))
			{
				int code = WSAGetLastError();
				if (code != WSA_IO_PENDING && code != WSAEFAULT)
				{
					onServerFunc(this, PS->hSocket, io_close, 0, 0);
					delete[] PS->data;
					PS->data = NULL;
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
			onServerFunc(this, PS->hSocket, io_close, 0, 0);
			delete[] PS->data;
			PS->data = NULL;
			delete PS;
			PS = NULL;
			return;
		}

		if (PS->offset < sizeof(DWORD) + size)
		{
			char *newData = new char[sizeof(DWORD) + size];

			if (!newData)
			{
				onServerFunc(this, PS->hSocket, io_close, 0, 0);
				delete[] PS->data;
				PS->data = NULL;
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
			dwRecvByte = 0;
			Flags = 0;
			if (WSARecv(PS->hSocket, &wsabuf, 1, &dwRecvByte, &Flags, (LPWSAOVERLAPPED)PS, NULL))
			{
				int code = WSAGetLastError();
				if (code != WSA_IO_PENDING && code != WSAEFAULT)
				{
					onServerFunc(this, PS->hSocket, io_close, 0, 0);
					delete[] PS->data;
					PS->data = NULL;
					delete PS;
					PS = NULL;
				}
				return;
			}
			return;
		}

		if (PS->size > sizeof(DWORD))
		{
			onServerFunc(this, PS->hSocket, io_recv, PS->data + sizeof(DWORD), PS->size - sizeof(DWORD));
		}

		delete[] PS->data;
		PS->data = new char[sizeof(DWORD)];
		PS->size = sizeof(DWORD);
	}
	else
	{

		onServerFunc(this, PS->hSocket, io_recv, PS->data, PS->bytes);
	}

	PS->offset = 0;
	PS->state = io_recv;
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

	dwRecvByte = 0;
	Flags = 0;
	if (WSARecv(PS->hSocket, &wsabuf, 1, &dwRecvByte, &Flags, (LPWSAOVERLAPPED)PS, NULL))
	{
		int code = WSAGetLastError();
		if (code != WSA_IO_PENDING && code != WSAEFAULT)
		{

			onServerFunc(this, PS->hSocket, io_close, 0, 0);
			delete[] PS->data;
			PS->data = NULL;
			delete PS;
			PS = NULL;
		}
	}
}

int SERVER::send_async(SOCKET hSocket, char *data, DWORD size)
{
	if (size > 65536000)
	{
		return 1;
	}
	SERVER_ST *Socket_ST = new SERVER_ST;
	memset(Socket_ST, 0, sizeof(SERVER_ST));
	Socket_ST->instance = this;
	Socket_ST->state = io_send;
	Socket_ST->offset = 0;
	WSABUF wsabuf;
	if (m_mate)
	{
		Socket_ST->data = new char[sizeof(DWORD) + size];
		Socket_ST->size = sizeof(DWORD) + size;
		wsabuf.buf = Socket_ST->data;
		wsabuf.len = Socket_ST->size;
		memcpy(wsabuf.buf, &size, sizeof(DWORD));
		memcpy(wsabuf.buf + sizeof(DWORD), data, size);
	}
	else
	{
		wsabuf.buf = data;
		wsabuf.len = size;
	}
	if (WSASend(hSocket, &wsabuf, 1, &Socket_ST->bytes, 0, (LPWSAOVERLAPPED)Socket_ST, NULL))
	{
		if (WSAGetLastError() != WSA_IO_PENDING)
		{
			delete[] Socket_ST->data;
			Socket_ST->data = NULL;
			delete Socket_ST;
			Socket_ST = NULL;
			return 1;
		}
	}
	
	return 0;
}

int SERVER::send_sync(SOCKET hSocket, char *data, DWORD size)
{

	if (size > 65536000)
	{
		return 1;
	}

	if (m_mate)
	{
		memcpy(data, &size, sizeof(DWORD));
		memcpy(data + sizeof(DWORD), data, size);
		if (send(hSocket, data, size + sizeof(DWORD), 0))
		{
			return 0;
		}
	}
	else
	{
		if (send(hSocket, data, size, 0))
		{
			return 0;
		}
	}

	return 1;
}

void SERVER::onSend(bool stop, PS_SERVER PS)
{
	SOCKET hSocket = PS->hSocket;
	delete[] PS->data;
	PS->data = NULL;
	delete PS;
	PS = NULL;
	if (stop)
	{
		closesocket(hSocket);
		onServerFunc(this, hSocket, io_stop, 0, 0);
		hSocket = INVALID_SOCKET;
	}
}

class CLIENT;

typedef struct CLIENT_ST
{
	OVERLAPPED Socket_ST;
	CLIENT *instance;
	int state;
	SOCKET hSocket;
	char *data;
	DWORD bytes;
	DWORD size;
	DWORD offset;
} PX_CLIENT, *PS_CLIENT;

class CLIENT
{
public:
	CLIENT(void);
	~CLIENT(void);
	int Init(char *host, unsigned short port, BOOL mate, int timeout);
	void OnConnect(bool ercode, PS_CLIENT Socket_ST);
	void onClose(bool ercode, PS_CLIENT Socket_ST);
	void onRecv(bool ercode, PS_CLIENT Socket_ST);
	int Recv(PS_CLIENT Socket_ST);
	int Close();
	int send_async(char *data, DWORD size);
	int send_sync(char *data, DWORD size);
	void onSend(bool ercode, PS_CLIENT Socket_ST);
	SOCKET get_socket()
	{
		return m_hSocket;
	}

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

int CLIENT::Init(char *host, unsigned short port, BOOL mate, int time)
{
	m_mate = mate;
	m_hSocket = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, 0, 0, WSA_FLAG_OVERLAPPED);
	if (INVALID_SOCKET == m_hSocket)
	{
		return WSAGetLastError();
	}
	if (CreateIoCompletionPort((HANDLE)m_hSocket, hEvent_Client, 0, 0) == NULL)
	{
		Close();
		return GetLastError();
	}
	sockaddr_in pSockaddr;
	pSockaddr.sin_family = AF_INET;
	pSockaddr.sin_addr.s_addr = inet_addr(host);
	pSockaddr.sin_port = htons(port);
	unsigned long on = 0;
	ioctlsocket(m_hSocket, FIONBIO, &on);
	connect(m_hSocket, (sockaddr *)&pSockaddr, sizeof(sockaddr));
	struct timeval timeout;
	fd_set r;
	FD_ZERO(&r);
	FD_SET(m_hSocket, &r);
	timeout.tv_sec = 0;
	timeout.tv_usec = time * 1000;
	if (select(m_hSocket, 0, &r, 0, &timeout) <= 0)
	{
		Close();
		return 1;
	}
	CLIENT_ST *Socket_ST = new CLIENT_ST;
	memset(Socket_ST, 0, sizeof(CLIENT_ST));
	Socket_ST->instance = this;
	Socket_ST->state = io_connt;
	Socket_ST->data = NULL;
	Socket_ST->size = 0;
	Socket_ST->offset = 0;
	PostQueuedCompletionStatus(hEvent_Client, 0, 0, (LPOVERLAPPED)Socket_ST);
	return 0;
}

void CLIENT::OnConnect(bool stop, PS_CLIENT Socket_ST)
{
	setsockopt(m_hSocket, SOL_SOCKET, 0x7010, NULL, 0);

	onClientFunc(this, m_hSocket, io_connt, NULL, 0);

	if (stop)
	{
		onClose(stop, Socket_ST);
		return;
	}

	delete[] Socket_ST->data;

	if (m_mate)
	{
		Socket_ST->data = new char[sizeof(DWORD)];
		Socket_ST->size = sizeof(DWORD);
	}
	else
	{
		Socket_ST->data = new char[cache];
		Socket_ST->size = cache;
	}

	Socket_ST->state = io_recv;
	Socket_ST->offset = 0;

	if (1 == Recv(Socket_ST))
	{
		onClose(stop, Socket_ST);
		return;
	}
}
void CLIENT::onRecv(bool stop, PS_CLIENT Socket_ST)
{
	if (stop)
	{
		onClose(stop, Socket_ST);
		return;
	}

	if (m_mate)
	{
		Socket_ST->offset += Socket_ST->bytes;
		if (Socket_ST->offset < Socket_ST->size)
		{
			if (Recv(Socket_ST) == 1)
			{
				onClose(stop, Socket_ST);
				return;
			}
			return;
		}
		DWORD size = *((DWORD *)(Socket_ST->data));
		if (size > 65536000)
		{
			onClose(stop, Socket_ST);
			return;
		}

		if (Socket_ST->offset < DWORD(sizeof(DWORD)) + size)
		{
			delete[] Socket_ST->data;
			Socket_ST->data = new char[sizeof(DWORD) + size];
			Socket_ST->size = sizeof(DWORD) + size;
			Socket_ST->offset = sizeof(DWORD);
			memcpy(Socket_ST->data, &size, sizeof(DWORD));
			if (1 == Recv(Socket_ST))
			{
				onClose(stop, Socket_ST);
				return;
			}
			return;
		}

		if (Socket_ST->size - sizeof(DWORD) > 0)
		{
			onClientFunc(this, m_hSocket, io_recv, Socket_ST->data + sizeof(DWORD), Socket_ST->size - sizeof(DWORD));
		}
		delete[] Socket_ST->data;
		Socket_ST->data = NULL;
		Socket_ST->data = new char[sizeof(DWORD)];
		Socket_ST->size = sizeof(DWORD);
	}
	else
	{
		onClientFunc(this, m_hSocket, io_recv, Socket_ST->data, Socket_ST->bytes);
	}

	Socket_ST->offset = 0;

	if (Recv(Socket_ST) == 1)
	{
		onClose(stop, Socket_ST);
		return;
	}
}

int CLIENT::Recv(PS_CLIENT Socket_ST)
{
	Socket_ST->instance = this;
	Socket_ST->state = io_recv;
	WSABUF wsabuf;
	wsabuf.buf = Socket_ST->data + Socket_ST->offset;
	wsabuf.len = Socket_ST->size - Socket_ST->offset;
	DWORD Flags = 0;
	if (WSARecv(m_hSocket, &wsabuf, 1, &Socket_ST->bytes, &Flags, (LPWSAOVERLAPPED)Socket_ST, NULL))
	{
		int ercode = WSAGetLastError();

		if (ercode == WSAEFAULT)
		{
			return 0;
		}
		else if (ercode != WSA_IO_PENDING)
		{
			return 1;
		}
	}

	return 0;
}

void CLIENT::onClose(bool stop, PS_CLIENT Socket_ST)
{
	delete[] Socket_ST->data;
	Socket_ST->data = NULL;
	delete Socket_ST;
	Socket_ST = NULL;
	onClientFunc(this, m_hSocket, io_stop, NULL, 0);
	Close();
}

int CLIENT::Close()
{
	closesockets(m_hSocket);
	m_hSocket = INVALID_SOCKET;
	return 0;
}

int CLIENT::send_async(char *data, DWORD size)
{
	if (size > 65536000)
	{
		return 1;
	}

	CLIENT_ST *Socket_ST = new CLIENT_ST;
	memset(Socket_ST, 0, sizeof(CLIENT_ST));
	Socket_ST->instance = this;
	Socket_ST->state = io_send;

	WSABUF wsabuf;

	if (m_mate)
	{
		Socket_ST->data = new char[sizeof(DWORD) + size];
		Socket_ST->size = sizeof(DWORD) + size;
		wsabuf.buf = Socket_ST->data;
		wsabuf.len = Socket_ST->size;
		memcpy(wsabuf.buf, &size, sizeof(DWORD));
		memcpy(wsabuf.buf + sizeof(DWORD), data, size);
	}
	else
	{
		Socket_ST->data = data;
		Socket_ST->size = size;
		wsabuf.buf = Socket_ST->data;
		wsabuf.len = Socket_ST->size;
	}

	if (WSASend(m_hSocket, &wsabuf, 1, &Socket_ST->bytes, 0, (LPWSAOVERLAPPED)Socket_ST, NULL))
	{
		int ercode = WSAGetLastError();
		if (ercode != WSA_IO_PENDING)
		{
			delete[] Socket_ST->data;
			Socket_ST->data = NULL;
			delete Socket_ST;
			Socket_ST = NULL;
			return 1;
		}
	}
	return 0;
}

int CLIENT::send_sync(char *data, DWORD size)
{

	if (size > 65536000)
	{
		return 1;
	}

	if (m_mate)
	{
		memcpy(data, &size, sizeof(DWORD));
		memcpy(data + sizeof(DWORD), data, size);
		if (send(m_hSocket, data, size + sizeof(DWORD), 0))
		{
			return 0;
		}
	}
	else
	{

		if (send(m_hSocket, data, size, 0))
		{
			return 0;
		}
	}

	return 1;
}

void CLIENT::onSend(bool stop, PS_CLIENT Socket_ST)
{

	if (stop)
	{
		onClose(stop, Socket_ST);
		return;
	}

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
		SERVER_ST *Socket_ST = NULL;
		bool stop = false;

		if (!GetQueuedCompletionStatus(hEvent_Server, &bytes, &key, (LPOVERLAPPED *)&Socket_ST, INFINITE))
		{
			stop = true;
		}

		SERVER *instance = Socket_ST->instance;
		if (Socket_ST->state == io_recv && bytes <= 0)
		{
			stop = true;
		}

		Socket_ST->bytes = bytes;

		if (instance->m_stop)
		{
			instance->onSend(true, Socket_ST);
			continue;
		}

		switch (Socket_ST->state)
		{
		case io_connt:
			instance->onAccept(stop, Socket_ST);
			break;
		case io_recv:
			instance->onRecv(stop, Socket_ST);
			break;
		case io_send:
			instance->onSend(stop, Socket_ST);
			break;
		}
	}

	_endthreadex(0);
	return 0;
}

unsigned __stdcall Worker_client(void *pParam)
{
	while (true)
	{
		ULONG bytes = 0;
		ULONG_PTR key = 0;
		CLIENT_ST *Socket_ST = NULL;
		bool stop = false;
		if (!GetQueuedCompletionStatus(hEvent_Client, &bytes, &key, (LPOVERLAPPED *)&Socket_ST, INFINITE))
		{
			stop = true;
		}
		CLIENT *instance = Socket_ST->instance;
		if (Socket_ST->state == io_recv && bytes <= 0)
		{
			stop = true;
		}
		Socket_ST->bytes = bytes;
		switch (Socket_ST->state)
		{
		case io_connt:
			instance->OnConnect(stop, Socket_ST);
			break;
		case io_recv:
			instance->onRecv(stop, Socket_ST);
			break;
		case io_send:
			instance->onSend(stop, Socket_ST);
			break;
		}
	}

	_endthreadex(0);
	return 0;
}

extern "C" __declspec(dllexport) int __stdcall socket_init(onSocket callback)
{
	WSAData wsa;
	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
	{
		return WSAGetLastError();
	}

	onServerFunc = callback;
	onClientFunc = callback;

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
	HANDLE threadHandle;
	for (int i = 0; i < worker; i++)
	{
		threadHandle = (HANDLE)_beginthreadex(NULL, 0, &Worker_server, NULL, 0, NULL);
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
	return (long long)dServer;
}

extern "C" __declspec(dllexport) int __stdcall socket_server_get(HANDLE hSocket)
{
	return ((SERVER *)hSocket)->get_socket();
}

extern "C" __declspec(dllexport) char *__stdcall socket_hostname(SOCKET socket)
{
	return gethostnames(socket);
}

extern "C" __declspec(dllexport) int __stdcall socket_server_close(SOCKET hSocket)
{
	return closesockets(hSocket);
}

extern "C" __declspec(dllexport) int __stdcall socket_server_send_async(HANDLE hSocket, SOCKET so, char *data, int size)
{
	return ((SERVER *)hSocket)->send_async(so, data, size);
}
extern "C" __declspec(dllexport) int __stdcall socket_server_send_sync(HANDLE hSocket, SOCKET so, char *data, int size)
{
	return ((SERVER *)hSocket)->send_sync(so, data, size);
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

extern "C" __declspec(dllexport) int __stdcall socket_client(char *host, unsigned short port, BOOL mete, int time)
{
	CLIENT *dClient = new CLIENT;
	if (0 != dClient->Init(host, port, mete, time))
	{
		delete dClient;
		dClient = NULL;
		return 0;
	}
	return (long long)dClient;
}

extern "C" __declspec(dllexport) int __stdcall socket_client_stop(HANDLE hSocket)
{
	if (IsBadReadPtr(hSocket, 4) != 0)
	{
		return 0;
	}
	CLIENT *dClient = ((CLIENT *)hSocket);
	dClient->Close();
	delete dClient;
	dClient = NULL;
	return 0;
}
extern "C" __declspec(dllexport) int __stdcall socket_client_send_async(HANDLE hSocket, char *data, int size)
{
	return ((CLIENT *)hSocket)->send_async(data, size);
}
extern "C" __declspec(dllexport) int __stdcall socket_client_send_sync(HANDLE hSocket, char *data, int size)
{
	return ((CLIENT *)hSocket)->send_sync(data, size);
}
extern "C" __declspec(dllexport) int __stdcall socket_client_get(HANDLE hSocket)
{
	return ((CLIENT *)hSocket)->get_socket();
}


BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}


void __stdcall callback(HANDLE Socket, SOCKET so, int type, char *data, int size)
{

	switch (type)
	{
	case 1:
		if (hServer == Socket)
		{
			char sendData[] = "AAAAAAAAAAAAAAAA";
			socket_server_send_async(Socket, so, sendData, sizeof(sendData));
		}
		if (hClient == Socket)
		{
			char sendData[] = "AAAAAAAAAAAAAAAA";
			socket_client_send_async(Socket, sendData, sizeof(sendData));
		}
		break;
	case 2:
		printf("hServer Received data: %.*s\n", size, data);
		break;
	}
}

int main()
{
	if (socket_init(callback) == 0)
	{
		hServer = (HANDLE)socket_server((char *)"0.0.0.0", 8800, 0);
		hClient = (HANDLE)socket_client((char *)"127.0.0.1", 8800, 0, 3000);
		printf("%s\n", "IS OK");
		Sleep(1000 * 60 * 60 * 30);
	}
	return 0;
}
