#include "http.h"

#include <string>
#include <map>
#include <vector>
#include <sstream>
#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>

void Http::DecodeUrlParam(const std::string& strUrl, std::string& strPathFile, std::map<std::string, std::string>& mapParam)
{
	std::vector<std::string> vecURLParts;
    boost::algorithm::split(vecURLParts, strUrl, boost::algorithm::is_any_of("?"));
	
	strPathFile = vecURLParts[0];
	if (vecURLParts.size() == 2) {
		std::vector<std::string> vecParams;
        boost::algorithm::split(vecParams, vecURLParts[1], boost::algorithm::is_any_of("&"));
		for (size_t i = 0; i < vecParams.size(); ++i) {
			std::vector<std::string> vecKeyValue;
            boost::algorithm::split(vecKeyValue, vecParams[i], boost::algorithm::is_any_of("="));
			if (vecKeyValue.size() == 2) {
				mapParam[vecKeyValue[0]] = vecKeyValue[1];
			}
		}
	}
}

bool Http::DecodeHttpRequestRangeLine(const std::string& strLine, int64_t& nBegin)
{
	std::string::size_type pos1 = strLine.find_first_of("0123456789");
	if (std::string::npos == pos1)
		return false;

	std::string::size_type pos2 = strLine.find_first_not_of("0123456789", pos1);
	if (std::string::npos == pos2)
		return false;

	std::string strBegin = strLine.substr(pos1, pos2 - pos1);

	try {
		nBegin = boost::lexical_cast<long>(strBegin);

		return true;
	}
	catch(const boost::bad_lexical_cast &e)
	{
		return false;
	}
	
}

bool Http::DecodeHttpRequestRangeLine(const std::string& strLine, int64_t& nBegin, int64_t& nEnd)
{
	std::string::size_type pos = strLine.find_first_of("0123456789");
	if (std::string::npos == pos)
		return false;

	std::string strRange = strLine.substr(pos);

	std::replace(strRange.begin(), strRange.end(), '-', ' ');
	std::replace(strRange.begin(), strRange.end(), ',', ' ');

	std::istringstream iss(strRange);
	if (!(iss >> nBegin))
		return false;

	nEnd = -1;
	iss >> nEnd;

	return true;
}


bool Http::DecodeHttpContentRange(const std::string& strLine, std::string &strBytesUnit, int64_t &nBegin, int64_t &nEnd, int64_t &nSize)
{
	std::string::size_type nNumPos = strLine.find_first_of("0123456789");
	if (std::string::npos == nNumPos) {
		return false;
	}

	strBytesUnit = strLine.substr(0, nNumPos);
	boost::algorithm::trim(strBytesUnit);

	std::string strRange = strLine.substr(nNumPos);

	//example:734-1233/1234
	std::replace(strRange.begin(), strRange.end(), '-', ' ');
	std::replace(strRange.begin(), strRange.end(), '/', ' ');

	std::istringstream iss(strRange);

	if (!(iss >> nBegin))
		return false;

	if (!(iss >> nEnd))
		return false;

	if (!(iss >> nSize))
		return false;

	return true;
}

bool Http::DecodeHttpRequestLine(const std::string& strLine, std::string& strReq, std::string& strPath, std::string& strHttpVer)
{
	std::vector<std::string> vecResult;
	std::string strReqLine = strLine;

	boost::algorithm::trim(strReqLine);
	boost::algorithm::split(vecResult, strReqLine, boost::algorithm::is_any_of(" \t\n\r"));

	if (vecResult.size() == 3) {
		strReq = boost::algorithm::trim_copy(vecResult[0]);
		strPath = boost::algorithm::trim_copy(vecResult[1]);
		strHttpVer = boost::algorithm::trim_copy(vecResult[2]);
		return true;
	}
	else {
		return false;
	}
}

bool Http::DecodeHttpResponseHead(const std::string& strLine, std::string &strField, std::string &strValue)
{
	std::string::size_type pos = strLine.find(':');
	if (std::string::npos == pos)
		return false;

	strField = strLine.substr(0, pos);
	strValue = strLine.substr(pos + 1);

	boost::algorithm::trim(strField);
	boost::algorithm::trim(strValue);

	return true;
}

bool Http::DecodeHttpStatusLine(const std::string& strLine, std::string& strVersion, int &nResponseCode)
{
	std::istringstream iss(strLine);

	iss >> strVersion;

	iss >> nResponseCode;

	if (!iss)
		return false;
	else
		return true;
}


bool HttpRequest::Decode(const char* pData, int nSize)
{
	std::vector<std::string> vecResult;
	//SplitString(std::string(pData, nSize), back_inserter(vecResult), std::string("\n"));
	std::string strSrc(pData, nSize);
	boost::algorithm::split(vecResult, strSrc, boost::algorithm::is_any_of("\n"));

	if (vecResult.size() < 2)
		return false;

	std::string strReq; std::string strHttpVer;
	if (!Http::DecodeHttpRequestLine(vecResult[0], strReq, m_strPathFile, strHttpVer))
		return false;

	for (size_t i = 1; i < vecResult.size(); i++) {
		boost::algorithm::trim(vecResult[i]);
		if (vecResult[i].size() > 0) {
			std::string strField, strValue;
			if (Http::DecodeHttpResponseHead(vecResult[i], strField, strValue)) {
				m_mapFieldValue.insert(make_pair(strField, strValue));
			}
			else {
				return false;
			}
		}
	}

	std::string strHost = m_mapFieldValue["Host"];
	if (strHost == "") {
		return false;
	}

	std::ostringstream oss;
	oss << "http://" << strHost;

	if (m_strPathFile.size() == 0 || m_strPathFile[0] != '/') {
		oss << "/";
	}
	oss << m_strPathFile;
	m_strUrl = oss.str().c_str();

	return true;
}


std::string HttpRequest::GetHttpRequestField(const std::string& strField) const
{
	HttpFieldValueMapT::const_iterator iter = m_mapFieldValue.find(strField);
	if (iter != m_mapFieldValue.end()) {
		return iter->second;
	}
	else {
		return "";
	}
}


bool HttpResponseHead::Decode(const char* pData, int nSize)
{
	InitMember();

	m_strResponseHead.assign(pData, nSize);

	std::vector<std::string> vecResponseLine;
	boost::algorithm::split(vecResponseLine, m_strResponseHead, boost::algorithm::is_any_of("\n"));

	size_t nLinesCount = vecResponseLine.size();

	if (nLinesCount < 3 || vecResponseLine[nLinesCount - 1].size() != 0)
		return false;

	std::string http_ver_str;
	if (!Http::DecodeHttpStatusLine(vecResponseLine[0], http_ver_str, m_nStatusCode))
		return false;

	for (size_t i = 1; i < nLinesCount - 2; i++) {
		std::string strField, strValue;
		if (Http::DecodeHttpResponseHead(vecResponseLine[i], strField, strValue)) {
			if (!DecodeResponseParameter(strField, strValue))
				return false;
			m_mapFieldValue.insert(make_pair(strField, strValue));
		}
		else {
			return false;
		}
	}

	return true;
}

bool HttpResponseHead::ExistField(const std::string& strField) const
{
	return m_mapFieldValue.find(strField) != m_mapFieldValue.end();
}

std::string HttpResponseHead::GetField(const std::string& strField) const
{
	HttpFieldValueMapT::const_iterator iter = m_mapFieldValue.find(strField);
	if (iter != m_mapFieldValue.end()) {
		return iter->second;
	}
	else {
		return "";
	}
}

std::list<std::string> HttpResponseHead::GetCookies() const
{
	std::list<std::string> listCookies;

	HttpFieldValueMapT::const_iterator iter;
	std::pair<HttpFieldValueMapT::const_iterator, HttpFieldValueMapT::const_iterator> ret;

	ret = m_mapFieldValue.equal_range("Set-Cookie");
	for (iter = ret.first; iter != ret.second; iter++) {
		listCookies.push_back(iter->second);
	}

	return listCookies;
}

bool HttpResponseHead::DecodeResponseParameter(const std::string& strField, const std::string& strValue)
{
	if (strField == "Content-Length") {
		std::istringstream iss(strValue);
		if (!(iss>>m_nContentLength))
			return false;
	}
	else if (strField == "Content-Range") {
		std::string strBytesUnit;
		if (!Http::DecodeHttpContentRange(strValue, strBytesUnit, m_nContentBeginPos, m_nContentEndPos, m_nContentSumLength))
			return false;
	}
	else if (strField == "Location" || strField == "location") {
		m_strRedirectUrl = strValue;
	}
	else if (strField == "Transfer-Encoding") {
		if (strValue.find("chunked") != std::string::npos) {
			m_bIsChunkTransferCoding = true;
		}
	}
	else {

	}

	return true;
}

void HttpResponseHead::InitMember()
{
	m_strResponseHead = "";
	m_nStatusCode = 0;

	m_strRedirectUrl = "";
	m_bIsChunkTransferCoding = false;

	m_nContentLength = -1;

	m_nContentBeginPos = -1;
	m_nContentEndPos = -1;
	m_nContentSumLength = -1;
}


int64_t HttpResponseHead::GetContentSumSize() const
{
	if (ExistField("Content-Range"))
		return m_nContentSumLength;

	if (ExistField("Content-Length"))
		return m_nContentLength;

	return -1;
}
