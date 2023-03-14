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

#ifndef PACKAGE_PYPI_HPP
#define PACKAGE_PYPI_HPP

#include "sharedDefs.h"
#include "filesystemHelper.h"
#include <filesystem>
#include <fstream>


class PYPI final
{
    PYPI() = delete;
    ~PYPI() = delete;
public:

    static void getPackages(const std::vector<std::string>& osRootFolders,
                            std::function<void(nlohmann::json&)> callback)
    {
        // Map to match fields
        static const std::map<std::string, std::string> PYPI_FIELDS
        {
            {"Name: ", "name"},
            {"Version: ", "version"},
            {"Summary: ", "description"},
            {"Home-page: ", "source"},
            {"Author: ", "vendor"}
        };

        // Parse the METADATA file
        auto parseMetadata = [&callback](const std::filesystem::path& p)
        {
            std::ifstream file(p);
            std::string line;

            nlohmann::json packageInfo;

            packageInfo["version"] = UNKNOWN_VALUE;
            packageInfo["groups"] = UNKNOWN_VALUE;
            packageInfo["description"] = UNKNOWN_VALUE;
            packageInfo["architecture"] = UNKNOWN_VALUE;
            packageInfo["format"] = "PYPI";
            packageInfo["source"] = UNKNOWN_VALUE;
            packageInfo["location"] = p.string();
            packageInfo["priority"] = UNKNOWN_VALUE;
            packageInfo["size"] = 0;
            packageInfo["vendor"] = UNKNOWN_VALUE;
            packageInfo["install_time"] = UNKNOWN_VALUE;
            packageInfo["multiarch"] = UNKNOWN_VALUE;

            while (std::getline(file, line))
            {
                const auto it
                {
                    std::find_if(PYPI_FIELDS.begin(), PYPI_FIELDS.end(),
                    [&line](const auto& element)
                    {
                        return line.find(element.first) != std::string::npos;
                    })
                };

                if (PYPI_FIELDS.end() != it)
                {
                    const auto& [key, value] { *it };
                    packageInfo[value] = line.substr(key.length());
                }
            }

            // Check if we have a name and version
            if (packageInfo.contains("name") && packageInfo.contains("version"))
            {
                callback(packageInfo);
            }
        };

        const auto parseBasedOnType = [&](const std::filesystem::path& p)
        {
            // Find folder that ends with egg-info or dist-info
            if (p.filename().string().find("egg-info") != std::string::npos)
            {
                // Check if is regular file or directory
                if (std::filesystem::is_regular_file(p))
                {
                    parseMetadata(p);
                }
                else if (std::filesystem::is_directory(p))
                {
                    parseMetadata(p / "PKG-INFO");
                }
            }
            else if (p.filename().string().find("dist-info") != std::string::npos)
            {
                // Check if is regular file or directory
                if (std::filesystem::is_regular_file(p))
                {
                    parseMetadata(p);
                }
                else if (std::filesystem::is_directory(p))
                {
                    parseMetadata(p / "METADATA");
                }
            }
        };


        for (const auto& osFolder : osRootFolders)
        {
            std::vector<std::string> expandedPaths;
            // Expand paths
            Utils::expandAbsolutePath(osFolder, expandedPaths);

            for (const auto& expandedPath : expandedPaths)
            {
                // Exist and is a directory
                if (std::filesystem::exists(expandedPath) &&
                    std::filesystem::is_directory(expandedPath))
                {
                    for (const std::filesystem::path& p : std::filesystem::directory_iterator(expandedPath))
                    {
                        // Find folder that ends with egg-info or dist-info
                        // and parse the METADATA/PKG-INFO file
                        parseBasedOnType(p);
                    }
                }
            }
        }
    }
};

#endif // PACKAGE_PYPI_HPP
