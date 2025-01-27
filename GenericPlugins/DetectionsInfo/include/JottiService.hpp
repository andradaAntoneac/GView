#pragma once
#include "IService.hpp"

class JottiService : public IService
{
  private:
    std::string name = "Jotti";

    std::map<std::string, std::string> detectionsMap;
    int noOfEngines;
    int noOfDetections;
    long long lastAnalysisDate;
    std::string errorMessage;

  public:
    std::map<std::string, std::string>& GetDetectionsMap();
    int GetNoOfEngines();
    int GetNoOfDetections();
    long long GetLastAnalysisDate();
    std::string GetErrorMessage();

    bool CurlResults(std::string_view& key, std::string& MD5, std::string& responseString) override;
    bool ParseResponse(json jsonVlaue) override;
    bool ParseResponseError(json jsonVlaue) override;
    std::string GetName() override;
};
