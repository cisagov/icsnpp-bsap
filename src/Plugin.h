// Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved.
#pragma once

#include <plugin/Plugin.h>
#include "bsap.h"

namespace plugin 
{
    namespace ICSNPP_BSAP
    {
        class Plugin : public ::plugin::Plugin
        {
            protected:
                virtual plugin::Configuration Configure();
        };

        extern Plugin plugin;
    }
}