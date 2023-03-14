/*
 * Wazuh SYSINFO
 * Copyright (C) 2015, Wazuh Inc.
 * February 3, 2017.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef PACKAGE_NPM_HPP
#define PACKAGE_NPM_HPP

#include "sharedDefs.h"
#include <filesystem>
#include <fstream>


class NPM final
{
    NPM() = delete;
    ~NPM() = delete;
public:

    static void getPackages(const std::vector<std::string>& osRootFolders,
                            std::function<void(nlohmann::json&)> callback)
    {
        // Map to match fields
        static const std::map<std::string, std::string> NPM_FIELDS
        {
            {"name: ", "name"},
            {"version: ", "version"},
            {"description: ", "description"},
            {"homepage: ", "source"},
        };

        // Parse the package.json file

        // Iterate over node_modules folders
        for (const auto& osRootFolder : osRootFolders)
        {
            const auto nodeModulesFolder { osRootFolder + "/node_modules" };
            if (std::filesystem::exists(nodeModulesFolder))
            {
                for (const auto& packageFolder : std::filesystem::directory_iterator(nodeModulesFolder))
                {
                    const auto packageJsonFile { packageFolder.path() / "package.json" };
                    if (std::filesystem::exists(packageJsonFile))
                    {
                        std::ifstream file(packageJsonFile);

                        nlohmann::json packageInfo;

                        packageInfo["version"] = UNKNOWN_VALUE;
                        packageInfo["groups"] = UNKNOWN_VALUE;
                        packageInfo["description"] = UNKNOWN_VALUE;
                        packageInfo["architecture"] = UNKNOWN_VALUE;
                        packageInfo["format"] = "NPM";
                        packageInfo["source"] = UNKNOWN_VALUE;
                        packageInfo["location"] = packageJsonFile.string();
                        packageInfo["priority"] = UNKNOWN_VALUE;
                        packageInfo["size"] = 0;
                        packageInfo["vendor"] = UNKNOWN_VALUE;
                        packageInfo["install_time"] = UNKNOWN_VALUE;
                        packageInfo["multiarch"] = UNKNOWN_VALUE;

                        // Read nlohmann::json from filesystem path.
                        nlohmann::json packageJson;
                        file >> packageJson;

                        // Iterate over fields
                        for (const auto& [key, value] : NPM_FIELDS)
                        {
                            if (packageJson.contains(key))
                            {
                                packageInfo[value] = packageJson[key];
                            }
                        }

                        if (packageInfo.contains("name"))
                        {
                            callback(packageInfo);
                        }

                    }
                }
            }
        }
    }
};

#endif // PACKAGE_NPM_HPP
