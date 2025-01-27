#pragma once

#include <string>
#include <ctime>
#include <nlohmann/json.hpp>
#include <curl/curl.h>
#undef MessageBox
using json = nlohmann::json;

class IService
{
  public:
    virtual bool CurlResults(std::string_view& key, std::string& MD5, std::string& responseString) = 0;
    virtual bool ParseResponse(json jsonVlaue)                                                     = 0;
    virtual bool ParseResponseError(json jsonVlaue)                                                = 0;
    virtual std::string GetName()                                                                  = 0;

    virtual std::map<std::string, std::string>& GetDetectionsMap() = 0;
    virtual int GetNoOfEngines()                                   = 0;
    virtual int GetNoOfDetections()                                = 0;
    virtual long long GetLastAnalysisDate()                        = 0;
    virtual std::string GetErrorMessage()                          = 0;
};

size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp);