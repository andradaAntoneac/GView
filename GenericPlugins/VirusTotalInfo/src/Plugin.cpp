#include "VirusTotalInfo.hpp"

namespace GView::GenericPlugins::VirusTotalInfo
{
    Plugin::Plugin(Reference<Object> object) : Window("Virus Total Detections", "d:c,w:45%,h:40%", WindowFlags::Sizeable)
    {
        this->APIkey = Application::GetAppSettings()->GetValue("VirusTotalAPIKey").ToStringView();
        
        auto desktop = AppCUI::Application::GetDesktop();
        this->parent = desktop->GetFocusedChild();
        this->object = object;

        this->sendButton      = Factory::Button::Create(this, "Send", "x:20%,y:75%,w:20%", SEND_BUTTON_ID);
        this->importButton    = Factory::Button::Create(this, "Import", "x:40%,y:75%,w:20%", SEND_BUTTON_ID);
        this->cancelButton    = Factory::Button::Create(this, "Cancel", "x:60%,y:75%,w:20%", CANCEL_BUTTON_ID);
        this->noDataMessage = Factory::TextArea::Create(
              this, "There is no data about this file. Would you like to send  request to VirusTotal?", "x:10%, y:10%, w:80%", TextAreaFlags::Readonly);

        this->hashLabel = Factory::Label::Create(this, "Hash(MD5)", "x:30%,y:10%,w:20%");
        this->filesHash = Factory::TextArea::Create(
              this, "something to add later", "x:40%, y:10%, w:30%, h:5%", TextAreaFlags::Readonly);

        if (!this->hasData) {
            this->sendButton->SetVisible(true);
            this->importButton->SetVisible(true);
            this->cancelButton->SetVisible(true);
            this->noDataMessage->SetVisible(true);

        } else {
            this->sendButton->SetVisible(false);
            this->importButton->SetVisible(false);
            this->cancelButton->SetVisible(false);
            this->noDataMessage->SetVisible(false);

            this->hashLabel->SetVisible(true);
            this->filesHash->SetVisible(true);
        }

        if (this->APIkey.empty()) {
            Dialogs::MessageBox::ShowWarning("Warning", "No API key found for the potential VirusTotal request !");
        }
      
    }

    bool Plugin::ParseJsonResponse(std::string jsonValue)
    {
           
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
}