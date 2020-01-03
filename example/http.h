#pragma once

#include <string>
#include <map>
#include <list>
#include <map>

class HttpDataSource
{
public:
    virtual ~HttpDataSource() {}

	virtual void* OpenFile(const std::string& strFile, int64_t offset, int nPreBuffSize = 2*1024*1024) = 0;
	virtual int64_t GetFileSize(void *pFileHandle) = 0;
	//virtual int64_t GetFileStartPos(const std::string& strFile) = 0;
	
	virtual int ReadData(void* pFileHandle, int64_t offset, char* pBuffer, int nSize) = 0;
	virtual std::string GetFileEtag(void *pFileHandle) = 0;
	virtual void CloseFile(void* pFileHandle) = 0;
};

class Http
{
public:
	enum HttpMethod//HTTP method
	{
		HM_GET,
		HM_POST,
		HM_PUT,
		HM_HEAD,
		HM_CONNECT,
		HM_DELETE,
		HM_OPTIONS,
		HM_TRACE
	};

	static void DecodeUrlParam(const std::string& strUrl, std::string& strPathFile, std::map<std::string, std::string>& mapParam);
	static bool DecodeHttpRequestRangeLine(const std::string& strLine, int64_t& nBegin);
	static bool DecodeHttpRequestRangeLine(const std::string& strLine, int64_t& nBegin, int64_t& nEnd);
	static bool DecodeHttpRequestLine(const std::string& strLine, std::string& strReq, std::string& strPath, std::string& strHttpVer);
	static bool DecodeHttpResponseHead(const std::string& strLine, std::string &strField, std::string &strValue);

	static bool DecodeHttpContentRange(const std::string& strLine, std::string &strBytesUnit, int64_t &nBegin, int64_t &nEnd, int64_t &nSize);

	static bool DecodeHttpStatusLine(const std::string& strLine, std::string& strVersion, int &nResponseCode);
};

class HttpRequest
{
public:
	typedef std::map<std::string, std::string> HttpFieldValueMapT;

	HttpRequest() : m_eHttpMethod(Http::HM_GET) {}

	virtual ~HttpRequest() {}

	bool Decode(const char* pData, int nSize);
	std::string GetHttpRequestField(const std::string& strField) const;

	std::string GetReqPathFile() const { return m_strPathFile; }

	const std::string& GetUrlObj() const { return m_strUrl; }
	const HttpFieldValueMapT& GetFieldKeyValue() const { return m_mapFieldValue; }

private:
	HttpFieldValueMapT m_mapFieldValue;

	//std::string m_strHttpRequestHead;
	std::string m_strHttpRequestData;
	std::string m_strPathFile;
	std::string m_strUrl;

	Http::HttpMethod m_eHttpMethod;
};

class HttpResponseHead
{
public:
	HttpResponseHead() {}
	virtual ~HttpResponseHead() {}

	bool Decode(const char* pData, int nSize);
	int GetStatusCode() const { return m_nStatusCode; }

	bool ExistField(const std::string& strField) const;
	std::string GetField(const std::string& strField) const;

	std::list<std::string> GetCookies() const;

	inline const std::string& GetRedirectUrl() const { return m_strRedirectUrl; }
	inline const std::string& GetDispositionFileName() const { return m_strDispositionFileName; }

	inline bool IsChunkTransferCoding() const { return m_bIsChunkTransferCoding; }

	int64_t GetContentSumSize() const;

	inline int64_t GetContentLength() const { return m_nContentLength; }
	inline int64_t GetContentBeginPos() const { return m_nContentBeginPos; }
	inline int64_t GetContentEndPos() const { return m_nContentEndPos; }

private:
	bool DecodeResponseParameter(const std::string& strField, const std::string& strValue);
	void InitMember();

	std::string m_strResponseHead;
	int m_nStatusCode;

	std::string m_strRedirectUrl;
	std::string m_strDispositionFileName;

	bool m_bIsChunkTransferCoding;

	int64_t m_nContentLength;

	int64_t m_nContentBeginPos;
	int64_t m_nContentEndPos;
	int64_t m_nContentSumLength;

	typedef std::multimap<std::string, std::string> HttpFieldValueMapT;
	HttpFieldValueMapT m_mapFieldValue;
};