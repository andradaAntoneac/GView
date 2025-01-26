#include "VirusTotalService.hpp"

size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp)
{
    ((std::string*) userp)->append((char*) contents, size * nmemb);
    return size * nmemb;
}

bool VirusTotalService::CurlResults(std::string_view& key, std::string& MD5, std::string& responseString)
{
    std::string URL = "https://www.virustotal.com/api/v3/files/";
    URL.append(MD5);

    CURL* curl = curl_easy_init();
    if (!curl) {
        return false;
    }

    curl_easy_setopt(curl, CURLOPT_URL, URL.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseString);

    struct curl_slist* headers = NULL;
    std::string header         = "x-apikey: ";
    header.append(key);
    headers = curl_slist_append(headers, "accept: application/json");
    headers = curl_slist_append(headers, header.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    CURLcode res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        return false;
    }

    long responseCode;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &responseCode);

    if (responseCode != 200) {
        return false;
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return true;
}

bool VirusTotalService::ParseResponse(json jsonValue)
{
    try {
        this->noOfDetections = 0;
        auto scanResults     = jsonValue["data"]["attributes"]["last_analysis_results"];
        for (auto& [antivirus, details] : scanResults.items()) {
            std::string result;
            if (details["result"].empty()) {
                result = "Undetected";
            } else {
                result = details["result"];
                this->noOfDetections++;
            }
            this->detectionsMap.insert({ antivirus, result });
        }

        this->noOfEngines      = this->detectionsMap.size();
        this->lastAnalysisDate = (jsonValue["data"]["attributes"]["last_analysis_date"]);

    } catch (const json::exception& e) {
        this->errorMessage = "Error in parsing the JSON response: \n";
        this->errorMessage.append(e.what());
        return false;
    }

    return true;
}

bool VirusTotalService::ParseResponseError(json jsonValue)
{
    try {
        this->errorMessage         = jsonValue["error"]["code"];
        std::string VTerrorMessage = jsonValue["error"]["message"];
        this->errorMessage.append("\n");
        this->errorMessage.append(VTerrorMessage);
        return true;
    } catch (const json::exception& e) {
        this->errorMessage = "Error in parsing the JSON response: \n";
        this->errorMessage.append(e.what());
        return false;
    }
    return true;
}

std::string VirusTotalService::GetName()
{
    return this->name;
}

std::map<std::string, std::string>& VirusTotalService::GetDetectionsMap()
{
    return this->detectionsMap;
}

int VirusTotalService::GetNoOfEngines()
{
    return this->noOfEngines;
}

int VirusTotalService::GetNoOfDetections()
{
    return noOfDetections;
}

long long VirusTotalService::GetLastAnalysisDate()
{
    return this->lastAnalysisDate;
}

std::string VirusTotalService::GetErrorMessage()
{
    return this->errorMessage;
}
