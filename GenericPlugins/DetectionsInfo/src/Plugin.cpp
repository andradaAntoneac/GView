#include "DetectionsInfo.hpp"
#include <fstream>
#include <iostream>

namespace GView::GenericPlugins::DetectionsInfo
{

Plugin::Plugin(Reference<Object> object) : Window("Detections", "d:c,w:40%,h:70%", WindowFlags::Sizeable)
{
    // add the service
    this->services.insert({ "Jotti", std::make_unique<JottiService>() });
    this->services.insert({ "VirusTotal", std::make_unique<VirusTotalService>() });

    string_view VirusTotalAPIKey = Application::GetAppSettings()->GetSection("Generic.DetectionsInfo").GetValue("VirusTotalAPIKey").ToString();
    this->credetials.insert({ "VirusTotal", VirusTotalAPIKey });
    this->credetials.insert({ "Jotti", VirusTotalAPIKey });

    auto desktop = AppCUI::Application::GetDesktop();
    this->parent = desktop->GetFocusedChild();
    this->object = object;

    this->importMessage = Factory::Label::Create(
          this, "We found the file's detections ready to import. Would you like to import the results from the last export?", "x:10%, y:10%, w:80%, h:30%");
    this->importButton = Factory::Button::Create(this, "Import", "x:30%,y:95%,w:20%", IMPORT_BUTTON_ID);
    this->cancelButton = Factory::Button::Create(this, "Cancel", "x:50%,y:95%,w:20%", CANCEL_BUTTON_ID);

    this->noDataMessage    = Factory::Label::Create(this, "Please select the service you want to get detections from:", "x:10%, y:10%, w:80%, h:30%");
    this->servicesComboBox = Factory::ComboBox::Create(this, "x: 25%, y:65%, w:50%", "");
    this->sendButton       = Factory::Button::Create(this, "Send", "x:40%,y:75%,w:20%", SEND_BUTTON_ID);

    this->hashLabel = Factory::Label::Create(this, "Hash(MD5)", "x:30%,y:5%,w:30%");
    this->filesHash = Factory::TextField::Create(this, "hash", "x:40%, y:5%, w:37%");

    this->exportButton         = Factory::Button::Create(this, "Export", "x:30%,y:95%,w:20%", EXPORT_BUTTON_ID);
    this->sortButton           = Factory::Button::Create(this, "Undetected last", "x:50%,y:95%,w:20%", SORT_BUTTON_ID);
    this->detectionReportLabel = Factory::Label::Create(this, "Results:", "x:20%,y:12%,w:20%");
    this->lastScanLabel        = Factory::Label::Create(this, "LastScan:", "x:40%,y:12%,w:40%");
    this->listView = Factory::ListView::Create(this, "x:10%,y:15%,w:80%,h:80%", { "n:Antivirus,a:l,w:30%", "n:Detection,a:c,w:70%" }, ListViewFlags::None);

    this->ComputeMD5Hash();
    this->CreateServiceList();
    if (this->CheckImportFile()) {
        this->ShowImportWindow();
    } else {
        this->ShowSendWindow();
    }

    if (VirusTotalAPIKey.empty()) {
        Dialogs::MessageBox::ShowWarning("Warning", "No API key found for the potential VirusTotal request !");
    }
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

bool Plugin::CreateServiceList()
{
    for (auto& [key, value] : this->services) {
        this->servicesComboBox->AddItem(key);
    }
    this->servicesComboBox->SetCurentItemIndex(0);
    return true;
}

bool Plugin::CreateListView()
{
    if (this->importMade) {
        this->listView->DeleteAllItems();
        for (auto& [antivirus, detection] : this->detectionsMap) {
            this->listView->AddItem({ antivirus, detection });
        }
    } else {
        this->listView->DeleteAllItems();
        for (auto& [antivirus, detection] : this->services[serviceKey]->GetDetectionsMap()) {
            this->listView->AddItem({ antivirus, detection });
        }
    }
    return true;
}

bool Plugin::CreateSortedListView()
{
    if (this->importMade) {
        this->listView->DeleteAllItems();
        for (auto& [antivirus, detection] : this->detectionsMap) {
            if (detection != "Undetected")
                this->listView->AddItem({ antivirus, detection });
        }
        for (auto& [antivirus, detection] : this->detectionsMap) {
            if (detection == "Undetected")
                this->listView->AddItem({ antivirus, detection });
        }
    } else {
        this->listView->DeleteAllItems();
        for (auto& [antivirus, detection] : this->services[serviceKey]->GetDetectionsMap()) {
            if (detection != "Undetected")
                this->listView->AddItem({ antivirus, detection });
        }
        for (auto& [antivirus, detection] : this->services[serviceKey]->GetDetectionsMap()) {
            if (detection == "Undetected")
                this->listView->AddItem({ antivirus, detection });
        }
    }

    return true;
}

bool Plugin::ExportResults()
{
    json jsonObject = { { "last_analysis_date", this->services[serviceKey]->GetLastAnalysisDate() },
                        { "last_analysis_results", this->services[serviceKey]->GetDetectionsMap() } };

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
        inputFile.close();

    } catch (const json::exception& e) {
        this->errorMessage = "Error in parsing the JSON file: \n";
        this->errorMessage.append(e.what());
        inputFile.close();
        return false;
    }

    return true;
}

bool Plugin::CheckImportFile()
{
    std::string filename = this->md5Hash;
    filename.append(".results.json");

    std::ifstream inputFile(filename);
    if (!inputFile.is_open()) {
        return false;
    }

    inputFile.close();
    return true;
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
            if (!this->credetials.contains("VirusTotal")) {
                Dialogs::MessageBox::ShowError("Error", "No APIKey to make the VirusTotal request!");
                break;
            }
            this->ShowDetectionsWindow();

            // matching the service from the map
            this->serviceKey = this->servicesComboBox->GetCurrentItemText();

            auto key = this->credetials[serviceKey];
            std::string responseString;
            bool curlHasError = !this->services[serviceKey]->CurlResults(key, this->md5Hash, responseString);
            try {
                json jsonObj = json::parse(responseString);

                if (curlHasError) {
                    if (!this->services[serviceKey]->ParseResponseError(jsonObj))
                        Dialogs::MessageBox::ShowError("Error", "Error parsing the response JSON!\n" + this->services[serviceKey]->GetErrorMessage());
                    else {
                        std::string errorTitle = serviceKey + "Error";
                        Dialogs::MessageBox::ShowError(errorTitle, this->services[serviceKey]->GetErrorMessage());
                        this->exportButton->SetVisible(false);
                        this->sortButton->SetVisible(false);
                        this->detectionReportLabel->SetVisible(false);
                        this->lastScanLabel->SetVisible(false);
                        this->listView->SetVisible(false);
                    }
                } else {
                    if (!this->services[serviceKey]->ParseResponse(jsonObj)) {
                        Dialogs::MessageBox::ShowError("Error", "Error parsing the response JSON!\n" + this->services[serviceKey]->GetErrorMessage());
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
            if (ImportAndParseResult()) {
                this->ShowDetectionsWindow();
                this->importMade = true;
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
            this->ShowSendWindow();
            break;
        }
        default:
            break;
        }
    }
    return true;
}

void Plugin::ShowImportWindow()
{
    this->importMessage->SetVisible(true);
    this->importButton->SetVisible(true);
    this->cancelButton->SetVisible(true);

    this->sendButton->SetVisible(false);
    this->noDataMessage->SetVisible(false);
    this->servicesComboBox->SetVisible(false);

    this->hashLabel->SetVisible(false);
    this->filesHash->SetVisible(false);
    this->exportButton->SetVisible(false);
    this->sortButton->SetVisible(false);
    this->detectionReportLabel->SetVisible(false);
    this->lastScanLabel->SetVisible(false);
    this->listView->SetVisible(false);
}
void Plugin::ShowSendWindow()
{
    this->sendButton->SetVisible(true);
    this->noDataMessage->SetVisible(true);
    this->servicesComboBox->SetVisible(true);

    this->importMessage->SetVisible(false);
    this->importButton->SetVisible(false);
    this->cancelButton->SetVisible(false);

    this->hashLabel->SetVisible(false);
    this->filesHash->SetVisible(false);
    this->exportButton->SetVisible(false);
    this->sortButton->SetVisible(false);
    this->detectionReportLabel->SetVisible(false);
    this->lastScanLabel->SetVisible(false);
    this->listView->SetVisible(false);
}
void Plugin::ShowDetectionsWindow()
{
    this->sendButton->SetVisible(false);
    this->noDataMessage->SetVisible(false);
    this->servicesComboBox->SetVisible(false);

    this->importMessage->SetVisible(false);
    this->importButton->SetVisible(false);
    this->cancelButton->SetVisible(false);

    this->hashLabel->SetVisible(true);
    this->filesHash->SetVisible(true);
    this->exportButton->SetVisible(true);
    this->sortButton->SetVisible(true);
    this->detectionReportLabel->SetVisible(true);
    this->lastScanLabel->SetVisible(true);
    this->listView->SetVisible(true);
}

void Plugin::OnAfterResize(int, int)
{
}
} // namespace GView::GenericPlugins::DetectionsInfo