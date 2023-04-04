#ifndef _BUILDER_H
#define _BUILDER_H

#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <builder/ivalidator.hpp>
#include <json/json.hpp>
#include <name.hpp>
#include <store/istore.hpp>
#include <utils/getExceptionStack.hpp>

#include "asset.hpp"
#include "policy.hpp"
#include "registry.hpp"

namespace builder
{

class Builder : public IValidator
{
private:
    std::shared_ptr<store::IStoreRead> m_storeRead;
    std::shared_ptr<internals::Registry> m_registry;

public:
    Builder(std::shared_ptr<store::IStoreRead> storeRead, std::shared_ptr<internals::Registry> registry)
        : m_storeRead {storeRead}
        , m_registry {registry}
    {
    }

    Policy buildPolicy(const base::Name& name) const
    {
        auto envJson = m_storeRead->get(name);
        if (std::holds_alternative<base::Error>(envJson))
        {
            throw std::runtime_error(fmt::format("Engine builder: Policy '{}' could not be obtained from the "
                                                 "store: {}.",
                                                 name.fullName(),
                                                 std::get<base::Error>(envJson).message));
        }

        Policy environment {std::get<json::Json>(envJson), m_storeRead, m_registry};

        return environment;
    }

    /**
     * @brief Build a asset route from the store.
     *
     * @param name Name of the route.
     * @return The route.
     * @throws std::runtime_error if the route could not be obtained from the store or if the route definition is
     * invalid.
     */
    Asset buildFilter(const base::Name& name) const
    {
        auto routeJson = m_storeRead->get(name);
        if (std::holds_alternative<base::Error>(routeJson))
        {
            throw std::runtime_error(fmt::format("Engine builder: Filter '{}' could not be obtained from the "
                                                 "store: {}.",
                                                 name.fullName(),
                                                 std::get<base::Error>(routeJson).message));
        }
        return Asset {std::get<json::Json>(routeJson), Asset::Type::FILTER, m_registry};
    }

    std::optional<base::Error> validatePolicy(const json::Json& json) const override
    {
        try
        {
            Policy env {json, m_storeRead, m_registry};
            env.getExpression();
        }
        catch (const std::exception& e)
        {
            return base::Error {utils::getExceptionStack(e)};
        }

        return std::nullopt;
    }

    std::optional<base::Error> validateIntegration(const json::Json& json) const override
    {
        try
        {
            Policy::getManifestAssets(json, m_storeRead, m_registry);
        }
        catch (const std::exception& e)
        {
            return base::Error {utils::getExceptionStack(e)};
        }

        return std::nullopt;
    }

    std::optional<base::Error> validateAsset(const json::Json& json) const override
    {
        try
        {
            // TODO: Remove asset type in Asset
            Asset asset {json, Asset::Type::DECODER, m_registry};
            asset.getExpression();
        }
        catch (const std::exception& e)
        {
            return base::Error {utils::getExceptionStack(e)};
        }

        return std::nullopt;
    }
};

} // namespace builder

#endif // _BUILDER_H
