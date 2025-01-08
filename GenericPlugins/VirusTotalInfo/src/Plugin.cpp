#include "VirusTotalInfo.hpp"
#include <fstream>
#include <iostream>
#include <ctime>
#include <curl/curl.h>
#undef MessageBox

namespace GView::GenericPlugins::VirusTotalInfo
{

Plugin::Plugin(Reference<Object> object) : Window("Virus Total Detections", "d:c,w:40%,h:70%", WindowFlags::Sizeable)
{
    this->APIkey = Application::GetAppSettings()->GetSection("AppCUI").GetValue("VirusTotalAPIKey").ToString();

    auto desktop = AppCUI::Application::GetDesktop();
    this->parent = desktop->GetFocusedChild();
    this->object = object;

    this->sendButton    = Factory::Button::Create(this, "Send", "x:20%,y:75%,w:20%", SEND_BUTTON_ID);
    this->importButton  = Factory::Button::Create(this, "Import", "x:40%,y:75%,w:20%", IMPORT_BUTTON_ID);
    this->cancelButton  = Factory::Button::Create(this, "Cancel", "x:60%,y:75%,w:20%", CANCEL_BUTTON_ID);
    this->noDataMessage = Factory::Label::Create(
          this, "There is no data about this file. Would you like to send a request to VirusTotal or import data?", "x:10%, y:10%, w:80%, h:30%");

    this->hashLabel = Factory::Label::Create(this, "Hash(MD5)", "x:30%,y:5%,w:30%");
    this->filesHash = Factory::TextField::Create(this, "hash", "x:40%, y:5%, w:37%");

    this->exportButton         = Factory::Button::Create(this, "Export", "x:30%,y:95%,w:20%", EXPORT_BUTTON_ID);
    this->sortButton           = Factory::Button::Create(this, "Undetected last", "x:50%,y:95%,w:20%", SORT_BUTTON_ID);
    this->detectionReportLabel = Factory::Label::Create(this, "Results:", "x:20%,y:12%,w:20%");
    this->lastScanLabel        = Factory::Label::Create(this, "LastScan:", "x:40%,y:12%,w:40%");
    this->listView = Factory::ListView::Create(this, "x:10%,y:15%,w:80%,h:80%", { "n:Antivirus,a:l,w:30%", "n:Detection,a:c,w:70%" }, ListViewFlags::None);

    this->sendButton->SetVisible(true);
    this->importButton->SetVisible(true);
    this->cancelButton->SetVisible(true);
    this->noDataMessage->SetVisible(true);

    this->hashLabel->SetVisible(false);
    this->filesHash->SetVisible(false);
    this->exportButton->SetVisible(false);
    this->sortButton->SetVisible(false);
    this->detectionReportLabel->SetVisible(false);
    this->lastScanLabel->SetVisible(false);
    this->listView->SetVisible(false);

    if (this->APIkey.empty()) {
        Dialogs::MessageBox::ShowWarning("Warning", "No API key found for the potential VirusTotal request !");
    }
}

bool Plugin::ParseJsonResponse(json jsonValue)
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
        this->noOfEngines = this->detectionsMap.size();

        this->lastAnalysisDate = jsonValue["data"]["attributes"]["last_analysis_date"];

        ComputeDetails();
    } catch (const json::exception& e) {
        this->errorMessage = "Error in parsing the JSON response: \n";
        this->errorMessage.append(e.what());
        return false;
    }

    return true;
}

bool Plugin::ParseJsonResponseError(json jsonValue)
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
}

bool Plugin::ComputeDetails()
{
    std::time_t time   = static_cast<std::time_t>(this->lastAnalysisDate);
    std::tm* localTime = std::localtime(&time);

    char buffer[50];
    if (std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", localTime)) {
        std::string scanMessage = "LastScan: ";
        scanMessage.append(const_cast<const char*>(buffer));
        this->lastScanLabel->SetText(scanMessage);
    } else {
        return false;
    }

    std::string reportMessage = "Results: ";
    reportMessage.append(std::to_string(this->noOfDetections));
    reportMessage.append("/");
    reportMessage.append(std::to_string(this->noOfEngines));
    this->detectionReportLabel->SetText(reportMessage);
}

bool Plugin::ComputeMD5Hash()
{
    const auto objectSize = this->object->GetData().GetSize();
    ProgressStatus::Init("Computing...", objectSize);
    OpenSSLHash md5(OpenSSLHashKind::Md5);
    const auto offset = 0ULL;
    const auto left   = this->object->GetData().GetSize();

    const char* format = "Reading [0x%.8llX/0x%.8llX] bytes...";
    if (objectSize > 0xFFFFFFFF) {
        format = "[0x%.16llX/0x%.16llX] bytes...";
    }

    LocalString<512> ls;
    const auto block             = this->object->GetData().GetCacheSize();
    const auto UpdateHashOnBlock = [&](uint64 offset, uint64 left) {
        do {
            CHECK(ProgressStatus::Update(offset, ls.Format(format, offset, objectSize)) == false, false, "");

            const auto sizeToRead = (left >= block ? block : left);
            left -= (left >= block ? block : left);

            const Buffer buffer = this->object->GetData().CopyToBuffer(offset, static_cast<uint32>(sizeToRead), true);
            CHECK(buffer.IsValid(), false, "");

            CHECK(md5.Update(buffer.GetData(), static_cast<uint32>(buffer.GetLength())), false, "");

            offset += sizeToRead;
        } while (left > 0);

        return true;
    };

    CHECK(UpdateHashOnBlock(offset, left), false, "");

    md5.Final();
    this->md5Hash = md5.GetHexValue();
    this->filesHash->SetText(this->md5Hash);

    return true;
}

bool Plugin::CreateListView()
{
    this->listView->DeleteAllItems();
    for (auto& [antivirus, detection] : this->detectionsMap) {
        this->listView->AddItem({ antivirus, detection });
    }
    return true;
}

bool Plugin::CreateSortedListView()
{
    this->listView->DeleteAllItems();
    for (auto& [antivirus, detection] : this->detectionsMap) {
        if (detection != "Undetected")
            this->listView->AddItem({ antivirus, detection });
    }
    for (auto& [antivirus, detection] : this->detectionsMap) {
        if (detection == "Undetected")
            this->listView->AddItem({ antivirus, detection });
    }
    return true;
}

bool Plugin::ExportResults()
{
    json jsonObject = { { "last_analysis_date", this->lastAnalysisDate }, { "last_analysis_results", this->detectionsMap } };

    std::string filename = this->md5Hash;
    filename.append(".results.json");

    std::ofstream outFile(filename);
    if (!outFile.is_open())
        return false;
    outFile << jsonObject.dump(4);
    outFile.close();
    return true;
}

bool Plugin::ImportAndParseResult()
{
    std::string filename = this->md5Hash;
    filename.append(".results.json");

    std::ifstream inputFile(filename);
    if (!inputFile.is_open()) {
        this->errorMessage = "Could not find file ";
        this->errorMessage.append(filename);
        this->errorMessage.append(" in the same directory with the analyzed file!");
        return false;
    }

    try {
        json jsonValue;
        inputFile >> jsonValue;
        this->noOfDetections = 0;
        auto scanResults     = jsonValue["last_analysis_results"];
        for (auto& [antivirus, detection] : scanResults.items()) {
            std::string result = detection;
            if (result != "Undetected")
                this->noOfDetections++;
            this->detectionsMap.insert({ antivirus, result });
        }
        this->noOfEngines = this->detectionsMap.size();

        this->lastAnalysisDate = jsonValue["last_analysis_date"];

        ComputeDetails();

    } catch (const json::exception& e) {
        this->errorMessage = "Error in parsing the JSON file: \n";
        this->errorMessage.append(e.what());
        return false;
    }

    return true;
}

size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp)
{
    ((std::string*) userp)->append((char*) contents, size * nmemb);
    return size * nmemb;
}

bool Plugin::CurlVirusTotalResults(std::string& responseString)
{
    std::string URL = "https://www.virustotal.com/api/v3/files/";

    // this->md5Hash = "03f38abed3555ed1ac256fe0edef620a351463c05a651ee95da258d9e5352e9b";
    URL.append(this->md5Hash);

    CURL* curl = curl_easy_init();
    if (!curl) {
        return false;
    }

    curl_easy_setopt(curl, CURLOPT_URL, URL.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseString);

    struct curl_slist* headers = NULL;
    std::string header         = "x-apikey: ";
    header.append(this->APIkey);
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

bool Plugin::OnEvent(Reference<Control> sender, Event eventType, int controlID)
{
    if (Window::OnEvent(sender, eventType, controlID)) {
        return true;
    }

    if (eventType == AppCUI::Controls::Event::ButtonClicked) {
        switch (controlID) {
        case SEND_BUTTON_ID: {
            if (this->APIkey.empty()) {
                Dialogs::MessageBox::ShowError("Error", "No APIKey to make the VirusTotal request!");
                break;
            }
            this->sendButton->SetVisible(false);
            this->importButton->SetVisible(false);
            this->cancelButton->SetVisible(false);
            this->noDataMessage->SetVisible(false);

            this->hashLabel->SetVisible(true);
            this->filesHash->SetVisible(true);
            this->exportButton->SetVisible(true);
            this->sortButton->SetVisible(true);
            this->detectionReportLabel->SetVisible(true);
            this->lastScanLabel->SetVisible(true);
            this->listView->SetVisible(true);

            ComputeMD5Hash();
            std::string responseString;
            bool curlHasError = !CurlVirusTotalResults(responseString);
            try {
                json jsonObj = json::parse(responseString);

                if (curlHasError) {
                    if (!ParseJsonResponseError(jsonObj))
                        Dialogs::MessageBox::ShowError("Error", "Error parsing the response JSON!\n" + this->errorMessage);
                    else {
                        Dialogs::MessageBox::ShowError("Virus Total Error", this->errorMessage);
                        this->exportButton->SetVisible(false);
                        this->sortButton->SetVisible(false);
                        this->detectionReportLabel->SetVisible(false);
                        this->lastScanLabel->SetVisible(false);
                        this->listView->SetVisible(false);
                    }
                } else {
                    if (!ParseJsonResponse(jsonObj)) {
                        Dialogs::MessageBox::ShowError("Error", "Error parsing the response JSON!\n" + this->errorMessage);
                    } else {
                        CreateListView();
                    }
                }

            } catch (const json::parse_error& e) {
                auto c = e.what();
                Dialogs::MessageBox::ShowError("Error", "Error getting the response JSON!");
            }

            break;
        }
        case IMPORT_BUTTON_ID: {
            ComputeMD5Hash();

            if (ImportAndParseResult()) {
                this->sendButton->SetVisible(false);
                this->importButton->SetVisible(false);
                this->cancelButton->SetVisible(false);
                this->noDataMessage->SetVisible(false);

                this->hashLabel->SetVisible(true);
                this->filesHash->SetVisible(true);
                this->exportButton->SetVisible(true);
                this->sortButton->SetVisible(true);
                this->detectionReportLabel->SetVisible(true);
                this->lastScanLabel->SetVisible(true);
                this->listView->SetVisible(true);

                CreateListView();
            } else {
                Dialogs::MessageBox::ShowError("Error Import", this->errorMessage);
            }
            break;
        }
        case EXPORT_BUTTON_ID: {
            if (ExportResults()) {
                Dialogs::MessageBox::ShowNotification("Export", "Results saved!");
            } else {
                Dialogs::MessageBox::ShowError("Error Export", "Something went wrong in saving the results!");
            }
            break;
        }
        case SORT_BUTTON_ID: {
            this->listView->SetVisible(true);
            if (this->undetectedLast) {
                this->sortButton->SetText("Undetected last");
                CreateListView();
            } else {
                this->sortButton->SetText("Sort");
                CreateSortedListView();
            }
            this->undetectedLast = !this->undetectedLast;
            break;
        }
        case CANCEL_BUTTON_ID: {
            this->Exit();
            break;
        }
        default:
            break;
        }
    }
}

void Plugin::OnAfterResize(int, int)
{
}
} // namespace GView::GenericPlugins::VirusTotalInfo