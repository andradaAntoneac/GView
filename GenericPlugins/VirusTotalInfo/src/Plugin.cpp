#include "VirusTotalInfo.hpp"
#include <fstream>
#include <iostream>
#include <ctime>


namespace GView::GenericPlugins::VirusTotalInfo
{

Plugin::Plugin(Reference<Object> object) : Window("Virus Total Detections", "d:c,w:40%,h:70%", WindowFlags::Sizeable)
{
    this->APIkey = Application::GetAppSettings()->GetSection("AppCUI").GetValue("VirusTotalAPIKey").ToString();

    auto desktop = AppCUI::Application::GetDesktop();
    this->parent = desktop->GetFocusedChild();
    this->object = object;

    this->sendButton    = Factory::Button::Create(this, "Send", "x:20%,y:75%,w:20%", SEND_BUTTON_ID);
    this->importButton  = Factory::Button::Create(this, "Import", "x:40%,y:75%,w:20%", SEND_BUTTON_ID);
    this->cancelButton  = Factory::Button::Create(this, "Cancel", "x:60%,y:75%,w:20%", CANCEL_BUTTON_ID);
    this->noDataMessage = Factory::TextArea::Create(
          this,
          "There is no data about this file. Would you like to send a request to VirusTotal or import data?",
          "x:10%, y:10%, w:80%",
          TextAreaFlags::Readonly);

    this->hashLabel            = Factory::Label::Create(this, "Hash(MD5)", "x:30%,y:5%,w:30%");
    this->filesHash            = Factory::TextArea::Create(this, "something to add later", "x:45%, y:3%, w:30%, h:5%", TextAreaFlags::Readonly);
    this->exportButton         = Factory::Button::Create(this, "Export", "x:30%,y:95%,w:20%", EXPORT_BUTTON_ID);
    this->sortButton           = Factory::Button::Create(this, "Sort", "x:50%,y:95%,w:20%", SORT_BUTTON_ID);
    this->detectionReportLabel = Factory::Label::Create(this, "Results:", "x:20%,y:12%,w:20%");
    this->lastScanLabel        = Factory::Label::Create(this, "LastScan:", "x:40%,y:12%,w:40%");

    if (!this->hasData) {
        // aici e prima imagine cand nu exista informatii despre fisier
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

    } else {
        // a doua imagine, exista informatii din request sau import
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
    }

    if (this->APIkey.empty()) {
        Dialogs::MessageBox::ShowWarning("Warning", "No API key found for the potential VirusTotal request !");
    }

    // partea asta o sa fie inlocuita de curl
    std::string filePath = "D:\\facultate\\RE\\data.json";
    std::ifstream inputFile(filePath);
    if (!inputFile.is_open()) {
        std::cerr << "Could not open file: " << filePath << std::endl;
    }

    try {
        json jsonObj;
        inputFile >> jsonObj;
        inputFile.close();
        if (!ParseJsonResponse(jsonObj)) {
            Dialogs::MessageBox::ShowError("Error", "Error parsing the response JSON!");
        } else {
            ComputeMD5Hash();
            CreateSortedListView();
        }

    } catch (const json::parse_error& e) {
        auto c = e.what();
        Dialogs::MessageBox::ShowError("Error", "Error getting the response JSON!");
    }
}

bool Plugin::ParseJsonResponse(json jsonValue)
{
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

    long long lastAnalysisDate = jsonValue["data"]["attributes"]["last_analysis_date"];
    std::time_t time           = static_cast<std::time_t>(lastAnalysisDate);
    std::tm* localTime         = std::localtime(&time);

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

    return true;
}

bool Plugin::ComputeMD5Hash()
{
    const auto objectSize = object->GetData().GetSize();
    ProgressStatus::Init("Computing...", objectSize);
    OpenSSLHash md5(OpenSSLHashKind::Md5);
    const auto offset = 0ULL;
    const auto left   = object->GetData().GetSize();

    const char* format = "Reading [0x%.8llX/0x%.8llX] bytes...";
    if (objectSize > 0xFFFFFFFF) {
        format = "[0x%.16llX/0x%.16llX] bytes...";
    }

    LocalString<512> ls;
    const auto block             = object->GetData().GetCacheSize();
    const auto UpdateHashOnBlock = [&](uint64 offset, uint64 left) {
        do {
            CHECK(ProgressStatus::Update(offset, ls.Format(format, offset, objectSize)) == false, false, "");

            const auto sizeToRead = (left >= block ? block : left);
            left -= (left >= block ? block : left);

            const Buffer buffer = object->GetData().CopyToBuffer(offset, static_cast<uint32>(sizeToRead), true);
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
    auto lv = Factory::ListView::Create(this, "x:10%,y:15%,w:80%,h:80%", { "n:Antivirus,a:l,w:30%", "n:Detection,a:c,w:70%" }, ListViewFlags::None);
    for (auto& [antivirus, detection] : this->detectionsMap) {
        lv->AddItem({ antivirus, detection });
    }
    return true;
}

bool Plugin::CreateSortedListView()
{
    auto lv = Factory::ListView::Create(this, "x:10%,y:15%,w:80%,h:80%", { "n:Antivirus,a:l,w:30%", "n:Detection,a:c,w:70%" }, ListViewFlags::None);
    for (auto& [antivirus, detection] : this->detectionsMap) {
        if (detection != "Undetected")
            lv->AddItem({ antivirus, detection });
    }
    for (auto& [antivirus, detection] : this->detectionsMap) {
        if (detection == "Undetected")
            lv->AddItem({ antivirus, detection });
    }
    return true;
}

bool Plugin::OnEvent(Reference<Control> sender, Event eventType, int controlID)
{
    if (Window::OnEvent(sender, eventType, controlID)) {
        return true;
    }
}

void Plugin::OnAfterResize(int, int)
{
}
} // namespace GView::GenericPlugins::VirusTotalInfo