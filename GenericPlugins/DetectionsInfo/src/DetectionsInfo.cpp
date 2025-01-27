#include "DetectionsInfo.hpp"

namespace GView::GenericPlugins::DetectionsInfo
{
extern "C" {
PLUGIN_EXPORT bool Run(const string_view command, Reference<GView::Object> object)
{
    if (command == "DetectionsInfo") {
        auto p = Plugin(object);
        p.Show();
        return true;
    }
    return false;
}

PLUGIN_EXPORT void UpdateSettings(IniSection sect)
{
    sect["Command.DetectionsInfo"] = Input::Key::Ctrl | Input::Key::T;
    sect["VirusTotalAPIKey"]       = "";
}
}
} // namespace GView::GenericPlugins::DetectionsInfo