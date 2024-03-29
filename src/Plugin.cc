// Copyright (c) 2023 Battelle Energy Alliance, LLC.  All rights reserved.

#include "Plugin.h"
#include "zeek/analyzer/Component.h"

namespace plugin
{
    namespace ICSNPP_BSAP
    {
        Plugin plugin;
    }
}

using namespace plugin::ICSNPP_BSAP;

zeek::plugin::Configuration Plugin::Configure()
{
    AddComponent(new zeek::analyzer::Component("BSAP",::analyzer::BSAP::BSAP_Analyzer::InstantiateAnalyzer));

    zeek::plugin::Configuration config;
    config.name = "ICSNPP::BSAP";
    config.description = "Bristol Standard Asynchronous Protocol over IP";
    config.version.major = 1;
    config.version.minor = 0;

    return config;
}