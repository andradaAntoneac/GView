#pragma once

#include "GView.hpp"
#include <nlohmann/json.hpp>
#include <map>

using json = nlohmann::json;
using namespace GView::Hashes;

namespace GView::GenericPlugins::VirusTotalInfo
{
static const uint32 SEND_BUTTON_ID   = 1;
static const uint32 IMPORT_BUTTON_ID = 2;
static const uint32 CANCEL_BUTTON_ID = 3;

static const uint32 EXPORT_BUTTON_ID = 4;
static const uint32 SORT_BUTTON_ID   = 5;

class Plugin : public Window
{
  private:
    Reference<Control> parent;

    bool undetectedLast    = false;
    string_view APIkey;
    std::string md5Hash;
    std::string errorMessage;
    std::map<std::string, std::string> detectionsMap;
    int noOfEngines;
    int noOfDetections;
    long long lastAnalysisDate;

  private:
    Reference<Object> object;
    Reference<Button> sendButton;
    Reference<Button> cancelButton;
    Reference<Button> importButton;
    Reference<Label> noDataMessage;

    Reference<Label> hashLabel;
    Reference<ListView> listView;
    Reference<TextField> filesHash;
    Reference<Label> detectionReportLabel;
    Reference<Label> lastScanLabel;
    Reference<Button> exportButton;
    Reference<Button> sortButton;

  public:
    Plugin(Reference<Object> object);
    bool ParseJsonResponse(json jsonValue);
    bool ParseJsonResponseError(json jsonValue);
    bool CreateListView();
    bool CreateSortedListView();
    bool ComputeMD5Hash();
    bool ExportResults();
    bool ImportAndParseResult();
    bool ComputeDetails();
    bool CurlVirusTotalResults(std::string& responseString);

    virtual void OnAfterResize(int newWidth, int newHeight) override;
    bool OnEvent(Reference<Control> sender, Event eventType, int controlID) override;
};
} // namespace GView::GenericPlugins::VirusTotalInfo