#pragma once

#include "GView.hpp"

namespace GView::GenericPlugins::VirusTotalInfo
{
static const uint32 SEND_BUTTON_ID = 1;
static const uint32 IMPORT_BUTTON_ID = 2;
static const uint32 CANCEL_BUTTON_ID   = 3;
class Plugin : public Window
{
private: 
	  Reference<Control> parent;
      bool hasData = true;
      string_view APIkey;
  
private: 
	  Reference<Object> object;
      Reference<Button> sendButton;
      Reference<Button> cancelButton;
      Reference<Button> importButton;
      Reference<TextArea> noDataMessage;

      Reference<Label> hashLabel;
      Reference<TextArea> filesHash;

  public:
      Plugin(Reference<Object> object);
      bool ParseJsonResponse(std::string jsonValue);

	  virtual void OnAfterResize(int newWidth, int newHeight) override;
      bool OnEvent(Reference<Control> sender, Event eventType, int controlID) override;
};
}