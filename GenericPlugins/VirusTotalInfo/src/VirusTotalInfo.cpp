#include "VirusTotalInfo.hpp"

namespace GView::GenericPlugins::VirusTotalInfo
{
extern "C" {
PLUGIN_EXPORT bool Run(const string_view command, Reference<GView::Object> object)
{
    if (command == "VirusTotalInfo") {
        auto p = Plugin(object);
        p.Show();
        return true;
    }
    return false;
}

PLUGIN_EXPORT void UpdateSettings(IniSection sect)
{
    sect["Command.VirusTotalInfo"] = Input::Key::Ctrl | Input::Key::T;
}
}
} // namespace GView::GenericPlugins::VirusTotalInfo