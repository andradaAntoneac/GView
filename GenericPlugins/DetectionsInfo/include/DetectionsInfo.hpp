#pragma once

#include "GView.hpp"
#include "VirusTotalService.hpp"
#include "JottiService.hpp"

using namespace GView::Hashes;

namespace GView::GenericPlugins::DetectionsInfo
{
static const uint32 SEND_BUTTON_ID   = 1;
static const uint32 IMPORT_BUTTON_ID = 2;
static const uint32 CANCEL_BUTTON_ID = 3;

static const uint32 EXPORT_BUTTON_ID = 4;
static const uint32 SORT_BUTTON_ID   = 5;

class Plugin : public Window
{
  protected:
    Reference<Control> parent;
    std::map<std::string, std::unique_ptr<IService>> services;
    std::map<std::string, string_view> credetials;

    bool undetectedLast = false;
    std::string md5Hash;
    std::string errorMessage;
    std::string serviceKey;

    bool importMade = false;
    std::map<std::string, std::string> detectionsMap;
    int noOfEngines;
    int noOfDetections;
    long long lastAnalysisDate;

  private:
    Reference<Object> object;

    Reference<Label> importMessage;
    Reference<Button> cancelButton;
    Reference<Button> importButton;

    Reference<ComboBox> servicesComboBox;
    Reference<Button> sendButton;
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
    bool CreateListView();
    bool CreateSortedListView();
    bool ComputeMD5Hash();
    bool ExportResults();
    bool ImportAndParseResult();
    bool ComputeDetails();
    bool CheckImportFile();
    bool CreateServiceList();

    void ShowImportWindow();
    void ShowSendWindow();
    void ShowDetectionsWindow();

    virtual void OnAfterResize(int newWidth, int newHeight) override;
    bool OnEvent(Reference<Control> sender, Event eventType, int controlID) override;
};
} // namespace GView::GenericPlugins::DetectionsInfo